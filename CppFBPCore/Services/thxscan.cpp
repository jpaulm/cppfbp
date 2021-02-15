#pragma optimize( "", off )
#include <stdio.h>
#include <malloc.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>

#include "cppfbp.h"
#include "thzcbs.h"
#define TRUE 1
#define FALSE 0

#if __OS2__ == 1
#define getc fgetc
#undef  EOF
#define EOF 0xff
#endif 



char curr_char;
char * o_ptr;

void scan_blanks(FILE *fp);

void scan_sym(FILE *fp, char * out_str);

label_ent * find_label(label_ent *label_tab, char name[32], char file[10],
	int label_count);
int thxgatrs(char * comp);
proc_ent *find_or_build_proc(char * nm);


proc_ent *proc_tab;
label_ent *label_curr;
char comp_name[200];
//bool eof_found = FALSE;
char eol = '\n';

bool TC(char c, FILE * fp) {
	if (curr_char == c) {
		*o_ptr = curr_char; o_ptr++;
		curr_char = getc(fp);
		return true;
	}
	return false;
}

bool TCO(char c, FILE * fp) {
	if (curr_char == c) {
		curr_char = getc(fp);
		return true;
	}
	return false;
}

bool TA(FILE * fp) {
	if (isalpha(curr_char)) {
		*o_ptr = curr_char; o_ptr++;
		curr_char = getc(fp);
		return true;
	}
	return false;
}

bool TN(FILE * fp) {
	if (isdigit(curr_char)) {
		*o_ptr = curr_char; o_ptr++;
		curr_char = getc(fp);
		return true;
	}
	return false;
}

bool TAI(FILE * fp) {
	if (isalpha(curr_char)) {
		*o_ptr = curr_char; o_ptr++;
		return true;
	}
	return false;
}

bool TNI(FILE * fp) {
	if (isdigit(curr_char)) {
		*o_ptr = curr_char; o_ptr++;
		return true;
	}
	return false;
}

void CC(FILE * fp) {
	*o_ptr = curr_char; o_ptr++;
	curr_char = getc(fp);
}

void SC(FILE * fp) {
	curr_char = getc(fp);
}

/*
Currently, no label at beginning, and no subnet support.

thxscan scans off the free form network definition, generating fixed format definitions (FFNDs)

To acommodate NoFlo, thxscan treats either end of line (EOL) or a comma as an end of clause;
	however, end of lines elsewhere are ignored... -

thxscan is either used by Thxgen to generate FFNDs, or by CppFBP in dynamic mode
*/

int thxscan(FILE *fp, label_ent *label_tab, char file_name[10])
{
	char *o_ptr;
	char out_str[255];
	//char fname[256];
	char out_num[8];
	size_t i, IIPlen, ret_code;
	char upstream_name[255];
	char upstream_port_name[255];
	int upstream_elem_no;
	char procname[255];


	proc_ent *proc_curr;
	//	proc_ent *proc_new;
	//	proc_ent *proc_find;
	cnxt_ent *cnxt_tab;
	cnxt_ent *cnxt_curr;
	cnxt_ent *cnxt_new;
	cnxt_ent *cnxt_hold;

	//	label_ent *label_new;

		//int label_ct;
	bool eq_arrow;
	IIP *IIP_ptr;


	char buffer[100];
	// major loop:
	while (true) {
		if (NULL == fgets(buffer, 100, fp))
			goto finish;
		if (0 == strcmp(buffer, "INPORT") || 0 == strcmp(buffer, "OUTPORT"))
			continue;

		ret_code = 0;

		curr_char = getc(fp);
		proc_tab = 0;
		cnxt_tab = 0;
		label_curr = label_tab;

		strcpy_s(label_curr->label, " ");
		strcpy_s(label_curr->file, file_name);
		label_curr->ent_type = 'L';

		IIPlen = -1;
		out_num[0] = '\0';
		cnxt_hold = 0;

		scan_blanks(fp);

		out_str[0] = 0;
		
		while (true) {
			scan_blanks(fp);
			if (!TCO(eol, fp))
				break;
		}
		if (TCO('\'', fp))
			goto Xs;       // quote found - scan off rest of IIP
	
		scan_sym(fp, out_str);

		if (TCO(':', fp)) {
			strcpy_s(label_curr->label, out_str);  // it was a label		  
			printf("Scanning Network: %s\n", out_str);
			scan_blanks(fp);
			out_str[0] = 0;

minorloop:
			while (true) {
				while (true) {
					scan_blanks(fp);
					if (!TCO(eol, fp))
						break;
				}
				comp_name[0] = 0;    // erase previous comp_name
				out_str[0] = 0;
				cnxt_hold = 0;
				IIPlen = -1;

				if (TCO(eol, fp))
					continue;

				if (TCO('\'', fp)) {
				Xs:		
					o_ptr = out_str;
					*o_ptr = '\0';
					goto get_rest_of_IIP;
				}

				scan_sym(fp, out_str);
				//}

				if (strlen(out_str) < 1)
					goto teof;

				strcpy_s(procname, out_str);
				printf("Procname: %s\n", procname);
				if (cnxt_hold != 0) {
					strcpy_s(cnxt_hold->downstream_name, procname);
					cnxt_hold = 0;
				}

				proc_curr = find_or_build_proc(procname);

				scan_blanks(fp);

				goto X3;

			get_rest_of_IIP:
				while (true) {
					if (TCO(EOF, fp)) {
						printf("EOF encountered within quoted string\n");
						ret_code = 4;
						goto exit;
					}

					if (TCO('\\', fp)) {  // backslash is escape character - following char copied unchanged
						CC(fp);
						continue;
					}

					if (TCO('\'', fp))
						break;

					CC (fp);

				}

				*o_ptr = '\0';
				IIPlen = static_cast<int>(o_ptr - out_str);
				IIP_ptr = (IIP *)malloc(IIPlen + 1);
				memcpy(IIP_ptr->datapart, out_str, IIPlen);
				IIP_ptr->datapart[IIPlen] = '\0';
				printf("IIP: %s\n", IIP_ptr->datapart);
				scan_blanks(fp);
				//IIPlen = -1;
				goto tArrow;


				// we have scanned off process name - now scan off optional component name

			X3:
				scan_blanks(fp);
				if (TCO('(', fp)) {
					scan_blanks(fp);

					//if (TCO(')', fp))  
					//   goto NN2;

					if (TCO('"', fp)) {           // this says that comp name may be surrounded by double quotes (not included in comp_name)
					}
					o_ptr = comp_name;      // if no data between brackets, comp_name will not be modified...
					*o_ptr = '\0';
					while (true) {
						if (TCO('"', fp))
							scan_blanks(fp);

						if (TCO(')', fp))
							break;

						CC(fp);
					}



					strcpy_s(proc_curr->comp_name, comp_name);
					if (strlen(comp_name) > 0) {
						printf("Comp name: %s\n", comp_name);
					}


					// comp scanned off, if any
					strcpy_s(upstream_name, procname);	    // in case this proc is the upstream of another arrow

					scan_blanks(fp);

					if (TCO('?', fp)) {
						proc_curr->trace = 1;
						scan_blanks(fp);
					}
				teof:
					if (TCO(EOF, fp))
						// this is a fudge because multiple nets are not currently supported
						goto exit;


					scan_blanks(fp);

					if (TCO(';', fp))
						// this is a fudge because multiple nets are not currently supported 
						goto exit;

					IIPlen = -1;
					if (TCO(',', fp)) {
						scan_blanks(fp);
						break;
					}


					if (TCO(eol, fp)) {

						scan_blanks(fp);
						break;
					}


					o_ptr = out_str;
					if (TC('*', fp))     /* automatic port */
						*o_ptr = '\0';

					else {
						scan_sym(fp, out_str);
					}
					scan_blanks(fp);

					strcpy_s(upstream_port_name, out_str);
					printf("Upstream port: %s\n", out_str);
					upstream_elem_no = 0;
					if (TCO('[', fp)) {
						o_ptr = out_num;
						while (true) {
							if (!(TN(fp)))
								break;
						}
					}

					if (TCO(']', fp)) {
						*o_ptr = '\0';
						upstream_elem_no = atoi(out_num);
					}
					else
						goto elemerr;
				}
			tArrow:
				scan_blanks(fp);
				eq_arrow = FALSE;
				if (TCO('-', fp))
					goto tGr;
				if (TCO('=', fp))
					eq_arrow = TRUE;
			tGr:
				if (TCO('>', fp)) {
					printf("Arrow\n");
					cnxt_new = (cnxt_ent *)malloc(sizeof(cnxt_ent));
					cnxt_new->succ = 0;
					cnxt_new->dropOldest = false;
					if (cnxt_tab == 0) {
						cnxt_tab = cnxt_new;
						label_curr->cnxt_ptr = cnxt_tab;
						cnxt_curr = cnxt_tab;
					}
					else {
						cnxt_curr->succ = cnxt_new;
						cnxt_curr = cnxt_new;
					}

					cnxt_hold = cnxt_new;
					if (IIPlen != -1) {
						strcpy_s(cnxt_hold->upstream_name, "!");
						cnxt_hold->upstream_port_name[0] = '\0';
						cnxt_hold->gen.IIPptr = IIP_ptr;
					}
					else {
						strcpy_s(cnxt_hold->upstream_name, upstream_name);
						strcpy_s(cnxt_hold->upstream_port_name, upstream_port_name);

						cnxt_hold->upstream_elem_no = upstream_elem_no;
					}
					cnxt_hold->capacity = -1;
					scan_blanks(fp);
					if (TCO('(', fp))
						o_ptr = out_num;
					while (true) {
						if (!(TN(fp)))
							break;
					}
					if (!(TCO(')', fp)))
						goto caperr;

					*o_ptr = '\0';
					cnxt_hold->capacity = atoi(out_num);
					scan_blanks(fp);



					cnxt_hold->downstream_elem_no = 0;
				}
				/* Scan off downstream port name */
				o_ptr = out_str;
				if (!(TC('*', fp)))
					goto Y2a;/* automatic port */
				*o_ptr = '\0';
				strcpy_s(cnxt_hold->downstream_port_name, out_str);  /* ext. conn */
				goto is_outport;
			Y2a:
				scan_sym(fp, out_str);
				strcpy_s(cnxt_hold->downstream_port_name, out_str);

			is_outport:

				printf("Downstream port: %s\n", cnxt_hold->downstream_port_name);

				scan_blanks(fp);
				if (!(TCO('[', fp)))
					break;
				o_ptr = out_num;
				while (true) {
					if (!(TN(fp)))
						break;
				}
				if (!(TCO(']', fp)))
					goto elemerr;
				*o_ptr = '\0';
				cnxt_hold->downstream_elem_no = atoi(out_num);
				//cnxt_hold = 0;
				scan_blanks(fp);
				
			}

			
			}

			break;

		elemerr:
			printf("Port element error\n");
			ret_code = 4;
			goto exit;

		caperr:
			printf("Capacity error\n");
			ret_code = 4;
			goto exit;

		nArrow:
			printf("No arrow found\n");
			ret_code = 4;

		exit:
			label_curr->succ = 0;   // temporary fix as we are only generating one network for now
			printf("\nSummary:\n");
			proc_curr = proc_tab;
			while (proc_curr != 0) {
				printf(" Process: %s (%s)\n", proc_curr->proc_name,
					proc_curr->comp_name);
				proc_curr = proc_curr->succ;
			}

			cnxt_hold = cnxt_tab;
			while (cnxt_hold != 0) {
				char up[200];
				char down[200];
				char elem[20];
				if (cnxt_hold->upstream_name[0] != '!') {
					strcpy_s(up, cnxt_hold->upstream_port_name);
					if (up[0] != '*') {
						strcat_s(up, "[");
						_itoa_s(cnxt_hold->upstream_elem_no, elem, 10);
						strcat_s(up, elem);
						strcat_s(up, "]");
					}
					strcpy_s(down, cnxt_hold->downstream_port_name);
					if (down[0] != '*') {
						strcat_s(down, "[");
						_itoa_s(cnxt_hold->downstream_elem_no, elem, 10);
						strcat_s(down, elem);
						strcat_s(down, "]");
					}
					printf(" Connection: %s %s -> %s %s\n",
						cnxt_hold->upstream_name,
						up,
						down,
						cnxt_hold->downstream_name);
				}
				else {
					strcpy_s(down, cnxt_hold->downstream_port_name);
					if (down[0] != '*') {
						strcat_s(down, "[");
						_itoa_s(cnxt_hold->downstream_elem_no, elem, 10);
						strcat_s(down, elem);
						strcat_s(down, "]");
					}
					printf(" IIP: -> %s %s\n",
						down,
						cnxt_hold->downstream_name);
					IIP_ptr = cnxt_hold->gen.IIPptr;
					printf("    \'");
					auto j = strlen(IIP_ptr->datapart);
					for (i = 0; i < j; i++)
						printf("%c", IIP_ptr->datapart[i]);
					printf("\'\n");
				}
				cnxt_hold = cnxt_hold->succ;
			}

		}
	finish:
		if (fclose(fp) != 0) {
			printf("Close error\n");
			if (ret_code == 0)
				ret_code = 2;
		}
		if (ret_code > 0) {
			// printf("Scan error\n");
			return(ret_code);
		}

		// printf("Scan finished\n");
		return (ret_code);
	}


	/*

	Scan off blanks

	Comments start with a # and continue until EOL
	*/

	void scan_blanks(FILE *fp) {

		//extern char curr_char;	

		for (;;) {

			
			if (TCO('#', fp)) {  // comment runs from #-sign to end of line
				for (;;) {
					if (TCO(EOF, fp))
						break;

					if (TCO(eol, fp))
						break;
					SC(fp);  // skip character
				}
				break;
			}
			if (!TCO(' ', fp))
				break;
		}
	}

	/*
	Scan off a network label or process name (this is used for ports as well, as we don't know if a string is a port until later...)

	Allowable characters are alphameric, hyphen, underscore; if character is preceded by backslash, will be accepted

	This routine exits when an nonallowed character (or EOL) is encountered
	*/
	inline void scan_sym(FILE *fp, char * out_str)
	{
		//extern char curr_char;
		char * o_ptr;

		o_ptr = out_str;
		while (true) {
			if (TA(fp) || TN(fp) || TC('_', fp) || TC('-', fp))
				continue;

			if (TCO('\\', fp)) { // as per discussion on https://groups.google.com/forum/#!searchin/flow-based-programming/commas -
							//             find "Special characters in process names" 
				CC(fp);
			}
			else
				break;

		}

		*o_ptr = '\0';
		return;
	}

	label_ent * find_label(label_ent *label_tab, char name[32], char file[10], int label_count)
	{
		label_ent * label_new;
		label_new = label_tab;
		while (label_new != 0) {

			if (label_new->label[0] == '\0')
				continue;
			if (label_new->ent_type != 'L')
				continue;
			if (strcmp(label_new->label, name) == 0 &&
				(strcmp(label_new->file, "\0") == 0 ||
					strcmp(label_new->file, file) == 0))
				break;
			label_new = label_new->succ;
		}
		return(label_new);
	}

	proc_ent * find_or_build_proc(char * name) {
		proc_ent * this_proc = proc_tab;
		proc_ent * last_proc = 0;
		while (this_proc != 0) {
			if (strcmp(this_proc->proc_name, name) == 0) break;
			last_proc = this_proc;
			this_proc = this_proc->succ;
		}

		if (this_proc == 0) {   // not found
			proc_ent * proc_new = (proc_ent *)malloc(sizeof(proc_ent));
			if (proc_tab == 0) {
				proc_tab = proc_new;
				label_curr->proc_ptr = proc_tab;
			}
			else {
				last_proc->succ = proc_new;
			}

			this_proc = proc_new;

			//proc_curr->proc_name[0] = '\0';	
			this_proc->succ = 0;
			this_proc->composite = 0;
			this_proc->faddr = 0;
			strcpy_s(this_proc->proc_name, name);
			this_proc->trace = 0;
			this_proc->comp_name[0] = '\0';
		}
		return this_proc;
	}