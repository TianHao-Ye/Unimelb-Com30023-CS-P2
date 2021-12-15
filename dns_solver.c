#include "dns_solver.h"

void modify_rep_id(char * raw_reply, dns_message *req_dns_message){
    raw_reply[ID_INDEX] = req_dns_message->id[0];
    raw_reply[ID_INDEX+1] = req_dns_message->id[1];
}

void decrement_ttl(int remaining_life, char *raw_reply){
    int ttl_index = index_of_ttl(raw_reply);
    unsigned char *hex = convert_decimal_to_hexadecimals(remaining_life);
    raw_reply[ttl_index] = hex[0];
    raw_reply[ttl_index+1] = hex[1];
    raw_reply[ttl_index+2] = hex[2];
    raw_reply[ttl_index+3] = hex[3];
    free(hex);
    hex = NULL;
}


int merge_four_hexdicimals(unsigned char num1, unsigned char num2, unsigned char num3, unsigned char num4){
    int decimal = 0;
    decimal += ((int)(num1>>4&0b00001111)) * pow(16, 7);
    decimal += ((int)(num1&0b00001111)) * pow(16, 6);
    decimal += ((int)(num2>>4&0b00001111)) * pow(16, 5);
    decimal += ((int)(num2&0b00001111)) * pow(16, 4);
    decimal += ((int)(num3>>4&0b00001111)) * pow(16, 3);
    decimal += ((int)(num3&0b00001111)) * pow(16, 2);
    decimal += ((int)(num4>>4&0b00001111)) * pow(16, 1);
    decimal += ((int)(num4&0b00001111)) * pow(16, 0);
    return decimal;
}

int index_of_ttl(char *raw_message){
    unsigned char *unsigned_message = convert_signed_to_unsigned_char(raw_message);
    int m_i = QNAME_INDEX;
    while(unsigned_message[m_i] != 0x00){
        int label_len = (int)unsigned_message[m_i++];
        m_i +=label_len;
    }
    m_i +=11;

    free(unsigned_message);
    unsigned_message = NULL;
    return m_i;
}

unsigned char *convert_decimal_to_hexadecimals(int decimalNumber){
    long remainder, quotient;
	int digit=0, j, temp;
	int hex_reversed[8] ={0};
	quotient = decimalNumber;
	while(quotient!=0) {
		temp = quotient % 16;
		hex_reversed[digit++]= temp;
		quotient = quotient / 16;
	}
    unsigned char *hex = (unsigned char *)malloc(4 *sizeof(unsigned char));
    assert(hex);
    hex[0] = (unsigned char)(hex_reversed[7]<<4 |hex_reversed[6]);
    hex[1] = (unsigned char)(hex_reversed[5]<<4 |hex_reversed[4]);
    hex[2] = (unsigned char)(hex_reversed[3]<<4 |hex_reversed[2]);
    hex[3] = (unsigned char)(hex_reversed[1]<<4 |hex_reversed[0]);
    
	return hex;
 }


/*modify rcode to4 adn qr to 1*/
void modify_request(char *message){
    unsigned char whole_byte;
    /*modify rcode to 4*/
    whole_byte = (unsigned char)message[RCODE_INDEX];
    whole_byte = whole_byte|0b10000100;
    message[RCODE_INDEX] = (char)whole_byte;

    /*modify qr to 1 if 0*/
    whole_byte = (unsigned char)message[QR_INDEX];
    whole_byte = whole_byte|0b10000000;
    message[QR_INDEX] = (char)whole_byte;
}

dns_message * create_new_dns_message(){
    dns_message *new_dns_message;
    new_dns_message = (dns_message *)malloc(sizeof(dns_message));
    assert(new_dns_message);
    new_dns_message->id[0] = ' ';
    new_dns_message->id[1] = ' ';
    new_dns_message->qr = 0;
    new_dns_message->q_type = 0;
    new_dns_message->question = NULL;
    new_dns_message->a_type = 0;
    new_dns_message->answer = NULL;
    new_dns_message->answer_number = 0;

    return new_dns_message;
}

dns_message *extract_message_info(char *raw_message){
    int message_index;

    unsigned char *message = convert_signed_to_unsigned_char(raw_message);

    dns_message *new_dns_message;
    new_dns_message = create_new_dns_message();
    
    /*get id*/
    new_dns_message->id[0] = message[ID_INDEX];
    new_dns_message->id[1] = message[ID_INDEX+1];
    
    /*get qr*/
    if(message[4]>>4 == 0b0000){
        new_dns_message->qr = 0;
    }
    else{
        new_dns_message->qr = 1;
    }

    /*get number of answer*/
    new_dns_message->answer_number = (int)merge_hexdicimals(message[AN_INDEX], message[AN_INDEX+1]);

    
    /*get question info*/
    message_index = extract_question_info(new_dns_message, QNAME_INDEX, message);
    
    /*get answer info*/
    if(new_dns_message->qr == 1){
        extract_answer_info(new_dns_message, message_index, message);
    }
    
    free(message);
    message = NULL;
    /*print_message_orderly(message_size, message);*/
    return new_dns_message;
}

void extract_answer_info(dns_message *dns_message, int initial_index, unsigned char message[]){
    int i;
    char *ans = NULL;
    char *ans_text = NULL;
    /*extract ans type*/
    int m_i = (initial_index + RELATIVE_DISTANCE_TO_ANS_TYPE);
    int type = merge_hexdicimals(message[m_i], message[m_i+1]);
    /*q_type =1 if AAAA, else 0*/
    int a_type = ((int)type == 28);
    dns_message->a_type = a_type;

    /*extract ans len and concrete ans*/
    m_i += RELATIVE_DISTANCE_FROM_ANS_TYPE_TO_LENGTH;
    int ans_len = (int)merge_hexdicimals(message[m_i], message[m_i+1]);
    m_i +=2;
    ans = (char *)malloc(ans_len *sizeof(char));
    assert(ans);
    ans_text = (char *)malloc(IPV6_BUFFERS_SIZE *sizeof(char));
    for (i=0; i< ans_len; i++){
        ans[i] = message[m_i++];
    }
    inet_ntop(AF_INET6, ans, ans_text, IPV6_BUFFERS_SIZE);
    dns_message->answer = ans_text;
    free(ans);
    ans = NULL;
}

/*return the message index after question area (the one after last btye in question area)*/
int extract_question_info(dns_message *dns_message, int initial_index, unsigned char message[]){
    int i;
    int d_i = 0;
    int domain_length = 0;
    int m_i = initial_index;
    char *q_name = NULL;
    int q_type = 0;
    /*first extract domain name*/
    while(message[m_i] != 0x00){
        int label_len = (int)message[m_i++];
        domain_length += (label_len+1);
        if(!q_name){
            q_name = (char *)malloc((label_len+1) *sizeof(char));
            assert(q_name);  
        }
        else{
            q_name = (char *)realloc(q_name, (domain_length) *sizeof(char));
            assert(q_name);
        }
        for(i=0; i< label_len; i++){
            q_name[d_i++] = (char)message[m_i++];
        }
        q_name[d_i++] = '.';
    }
    q_name[--d_i] = '\0';
    dns_message->question = q_name;
    
    /*then extract question type, m_i is null now*/
    int type = merge_hexdicimals(message[m_i+1], message[m_i+2]);
    
    m_i +=5;
    /*q_type =1 if AAAA, else 0*/
    q_type = ((int)type == 28);
    dns_message->q_type = q_type;
    
    return m_i;
}

unsigned char *convert_signed_to_unsigned_char(char *raw_message){
    int i;
    int message_length = (int)(unsigned char)raw_message[1];
    message_length +=2;
    unsigned char *message = (unsigned char *)malloc((message_length+1) * sizeof(unsigned char));
    assert(message);
    for(i=0;i<message_length;i++){
        message[i] = (unsigned char)raw_message[i];
    }
    message[i] = '\0';
    return message;
}

int merge_hexdicimals(int num1, int num2){
    return (num1<<8)|(num2);
}

void logging(FILE *f, dns_message *dns_message){
    char *my_time = get_time();

    /*if request*/
    if(dns_message->qr == 0){
        fprintf(f, "%s %s %s\n", my_time, "requested", dns_message->question);
        /*if non-AAAA*/
        if(dns_message->q_type !=1){
            fprintf(f, "%s %s\n", my_time, "unimplemented request");
        }
        
    }
    /*if reply*/
    else{
        if(dns_message->answer_number == 0){
            ;
        }
        else if(dns_message->a_type == 1){
            fprintf(f, "%s %s %s %s\n", my_time, dns_message->question, "is at", dns_message->answer);
        }
    }

    fflush(f);
    free(my_time);
    my_time = NULL;
}

char *add_get_time(time_t passed_time){
    time_t rawtime;
    struct tm *info;
    char *my_time = (char *)malloc(TIME_SIZE *sizeof(char));
    assert(my_time);
    time(&rawtime);
    rawtime +=passed_time;
    info = localtime(&rawtime);
    strftime(my_time, TIME_SIZE,"%FT%T%z", info);
    return my_time;
}

char *get_time(){
    time_t rawtime;
    struct tm *info;
    char *my_time = (char *)malloc(TIME_SIZE *sizeof(char));
    assert(my_time);
    time(&rawtime);
    info = localtime(&rawtime);
    strftime(my_time, TIME_SIZE,"%FT%T%z", info);
    return my_time;
}
