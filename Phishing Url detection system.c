#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>

#define MAX 2000

/* ===================== WHITELIST & BLACKLIST (IN CODE) ===================== */


char *WHITELIST[] = {
    "google.com",
    "facebook.com",
    "youtube.com"
};
int WHITELIST_SIZE = 3;

char *BLACKLIST[] = {
    "badphish.com",
    "phishing-bank.xyz",
    "evil-login.ru",
    "malicious.example"
};
int BLACKLIST_SIZE = 4;

/* newline remove */
void remove_newline(char s[])
{
    s[strcspn(s, "\r\n")] = 0;
}

/* string lowercase */
void to_lower(char s[])
{
    int i;
    for (i = 0; s[i]; i++)
    {
        s[i] = (char)tolower((unsigned char)s[i]);
    }
}

/* domain extractor */
void get_domain(char url[], char domain[])
{
    int i = 0, j = 0;

    if (strncmp(url, "http://", 7) == 0) i = 7;
    else if (strncmp(url, "https://", 8) == 0) i = 8;

    while (url[i] != '\0' && url[i] != '/' && url[i] != ':' &&
           url[i] != '?' && url[i] != '#')
    {
        domain[j++] = url[i++];
    }
    domain[j] = '\0';

    /* remove www. */
    if (strncmp(domain, "www.", 4) == 0)
    {
        int k;
        for (k = 0; domain[k + 4] != '\0'; k++) domain[k] = domain[k + 4];
        domain[k] = '\0';
    }
}

/* y/n validation */
char ask_yes_no(char prompt[])
{
    while (1)
    {
        char ans[50];
        int k = 0;
        char ch;

        printf("%s", prompt);
        if (fgets(ans, sizeof(ans), stdin) == NULL) return 'n';
        remove_newline(ans);

        while (ans[k] && isspace((unsigned char)ans[k])) k++;
        ch = (char)tolower((unsigned char)ans[k]);

        if (ch == 'y' || ch == 'n') return ch;

        printf("Invalid input! Only 'y' or 'n' allowed.\n");
    }
}

/* open url (Windows / Linux) */
void open_url(char url[])
{
#ifdef _WIN32
    char cmd[MAX + 30];
    sprintf(cmd, "start \"\" \"%s\"", url);
    system(cmd);
#else
    char cmd[MAX + 60];
    sprintf(cmd, "xdg-open \"%s\"", url);
    system(cmd);
#endif
}

/* ===================== LIST MATCH (WHITELIST/BLACKLIST) ===================== */
int domain_in_list(char domain[], char *list[], int size)
{
    int i;
    for (i = 0; i < size; i++)
    {
        if (strcmp(domain, list[i]) == 0) return 1;
    }
    return 0;
}

/* heuristic scoring 0-100 */
int heuristic_score(char url[])
{
    int score = 0;

    /* risky: http */
    if (strncmp(url, "http://", 7) == 0) score += 20;

    /* long url */
    if ((int)strlen(url) > 60) score += 15;

    /* @ found */
    if (strchr(url, '@') != NULL) score += 30;

    /* keyword check (lowercase copy) */
    {
        char u[MAX];
        strncpy(u, url, MAX - 1);
        u[MAX - 1] = '\0';
        to_lower(u);

        if (strstr(u, "login") != NULL) score += 20;
        else if (strstr(u, "verify") != NULL) score += 20;
        else if (strstr(u, "bank") != NULL) score += 20;
        else if (strstr(u, "password") != NULL) score += 20;
    }

    if (score > 100) score = 100;
    return score;
}

int main()
{
    while (1)
    {
        char url[MAX], domain[500];

        printf("\n============================\n");
        printf("   Phishing URL Detector\n");
        printf("============================\n");

        printf("Enter URL: ");
        if (fgets(url, sizeof(url), stdin) == NULL) break;
        remove_newline(url);

        if (url[0] == '\0')
        {
            printf("Empty URL! Try again.\n");
            continue;
        }

        /* Feature-1: domain extract */
        get_domain(url, domain);
        to_lower(domain);

        if (strlen(domain) == 0)
        {
            printf(" No Domain extract !\n");
        }
        else
        {
            printf("\nExtracted Domain: %s\n", domain);

            /* Feature-4: whitelist bypass */
            if (domain_in_list(domain, WHITELIST, WHITELIST_SIZE))
            {
                printf("✅ WHITELISTED -> SAFE\n");
                printf("Score: 0/100\n");

                if (ask_yes_no("Open this link? (y/n): ") == 'y')
                {
                    printf("Opening...\n");
                    open_url(url);
                }
                else
                {
                    printf("Okay, not opening.\n");
                }
            }
            /* Feature-2: blacklist check */
            else if (domain_in_list(domain, BLACKLIST, BLACKLIST_SIZE))
            {
                printf("❌ BLACKLISTED -> PHISHING (UNSAFE)\n");
                printf("Score: 100/100\n");
                printf("Link will NOT be opened.\n");
            }
            /* Feature-3: heuristic scoring */
            else
            {
                int score = heuristic_score(url);
                printf("\nScore: %d/100\n", score);

                /* Feature-5: result + Feature-6: open option */
                if (score >= 60)
                {
                    printf("Result: ❌ PHISHING (UNSAFE)\n");
                    printf("Link will NOT be opened.\n");
                }
                else if (score >= 30)
                {
                    printf("Result: ⚠️ SUSPICIOUS (UNSAFE)\n");
                    printf("Warning: This link may be risky!\n");


                    if (ask_yes_no("Open this link anyway? (y/n): ") == 'y')
                    {
                        printf("Opening...\n");
                        open_url(url);
                    }
                    else
                    {
                        printf("Okay, not opening.\n");
                    }
                }
                else
                {
                    printf("Result: ✅ SAFE\n");

                    if (ask_yes_no("Open this link? (y/n): ") == 'y')
                    {
                        printf("Opening...\n");
                        open_url(url);
                    }
                    else
                    {
                        printf("Okay, not opening.\n");
                    }
                }
            }
        }

        if (ask_yes_no("\nCheck another URL? (y/n): ") == 'n')
        {
            printf("Goodbye!\n");
            break;
        }
    }

    return 0;
}
