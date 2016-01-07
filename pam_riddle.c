#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <security/pam_ext.h>

#define byte unsigned char
#define MAXRIDDLES 1000

struct riddle
{
    char quest[1000];
    byte ans_hash[SHA256_DIGEST_LENGTH];
};

void sha256hash(char* plaintext, byte* output)
{
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, plaintext, strlen(plaintext));
    SHA256_Final(output, &sha256);
};

int loadRiddles(struct riddle *riddles)
{
    FILE *questions=fopen("/usr/share/riddles/questions", "rt"), *answers=fopen("/usr/share/riddles/answers", "rb");
    if(questions==NULL || answers==NULL)
        return -1;
    int cnt=0;

    while(fscanf(questions, "%[^\n]\n", riddles[cnt].quest)==1)
    {
        int tmp=strlen(riddles[cnt].quest);
        riddles[cnt].quest[tmp]='\n';
        riddles[cnt].quest[tmp+1]='\0';
        fread(riddles[cnt].ans_hash, SHA256_DIGEST_LENGTH, 1, answers);
        ++cnt;
    }

    fclose(questions);
    fclose(answers);
    return cnt;
}

PAM_EXTERN int pam_sm_authenticate( pam_handle_t *pamh, int flags, int argc, const char **argv )
{
    srand(time(NULL));
    struct riddle riddles[MAXRIDDLES];
    int riddlenum=loadRiddles(riddles);
    if(riddlenum<0)
        return PAM_AUTH_ERR;

    int pick=riddlenum<=1?0:rand()%riddlenum;

    struct pam_conv *pam_convp;
    struct pam_message *pam_msgp;
    struct pam_response *pam_resp = NULL;

    int retval = pam_get_item(pamh, PAM_CONV, (const void **)&pam_convp);
    if(retval!=PAM_SUCCESS)
        return retval;

    pam_msgp = (struct pam_message *)calloc(1, sizeof(struct pam_message));
    pam_msgp->msg_style=PAM_PROMPT_ECHO_ON;
    pam_msgp->msg=riddles[pick].quest;
    (pam_convp->conv)(1, (const struct pam_message **)&pam_msgp, &pam_resp, pam_convp->appdata_ptr);

    if(pam_resp==NULL || pam_resp->resp==NULL)
        return PAM_AUTH_ERR;

    byte hash[SHA256_DIGEST_LENGTH];
    sha256hash(pam_resp->resp, hash);

    if(memcmp(hash, riddles[pick].ans_hash, SHA256_DIGEST_LENGTH)!=0)
        return PAM_AUTH_ERR;

    free(pam_msgp);
    free(pam_resp);
    return PAM_SUCCESS;
}
