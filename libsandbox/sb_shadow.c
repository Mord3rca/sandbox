#include "headers.h"
#include "sb_shadow.h"
#include "libsandbox.h"

#define SB_SHADOW_MAX_USER  64
#define SB_SHADOW_MAX_GROUP 64

#define PASSWD_NAME_STR_SIZE 64
#define PASSWD_PASS_STR_SIZE 64
#define PASSWD_GECO_STR_SIZE 128

#define GROUP_NAME_STR_SIZE  64
#define GROUP_PASS_STR_SIZE  64
#define GROUP_MEM_ARRAY_SIZE 24

#define SB_SHADOW_LINE_BUFF_SIZE 1024

static char *eroot;

static bool _sb_shadow_init = false;

static struct passwd *(*sb_shadow_real_getpwuid)(uid_t) = NULL;
static struct passwd *(*sb_shadow_real_getpwnam)(const char*) = NULL;

static struct group *(*sb_shadow_real_getgrgid)(gid_t) = NULL;
static struct group *(*sb_shadow_real_getgrnam)(const char*) = NULL;

static int (*sb_shadow_real_getgrouplist)(const char*, gid_t, gid_t*, int*) = NULL;

static struct passwd *passwd_entries[SB_SHADOW_MAX_USER] = {0};
static struct group *group_entries[SB_SHADOW_MAX_GROUP] = {0};

static struct passwd *_new_passwd_struct(char line[SB_SHADOW_LINE_BUFF_SIZE])
{
	struct passwd *p = malloc(sizeof(struct passwd));
	char *saveptr;
	char *name = strtok_r(line, ":", &saveptr);
	char *passwd = strtok_r(NULL, ":", &saveptr);
	char *uid = strtok_r(NULL, ":", &saveptr);
	char *gid = strtok_r(NULL, ":", &saveptr);
	char *gecos = strtok_r(NULL, ":", &saveptr);
	char *dir = strtok_r(NULL, ":", &saveptr);
	char *shell = strtok_r(NULL, ":", &saveptr);

	p->pw_name = malloc(PASSWD_NAME_STR_SIZE);
	p->pw_passwd = malloc(PASSWD_PASS_STR_SIZE);
	p->pw_gecos = malloc(PASSWD_GECO_STR_SIZE);
	p->pw_dir = malloc(PATH_MAX);
	p->pw_shell = malloc(PATH_MAX);

	strncpy(p->pw_name, name, PASSWD_NAME_STR_SIZE);
	strncpy(p->pw_passwd, passwd, PASSWD_PASS_STR_SIZE);
	p->pw_uid = atoi(uid);
	p->pw_gid = atoi(gid);
	strncpy(p->pw_gecos, gecos, PASSWD_GECO_STR_SIZE);
	strncpy(p->pw_dir, dir, PATH_MAX);
	strncpy(p->pw_shell, shell, PATH_MAX);

	return p;
}

static struct group *_new_group_struct(char line[SB_SHADOW_LINE_BUFF_SIZE])
{
	int i;
	char *saveptr = line;

	char *name = strsep(&saveptr, ":");
	char *passwd = strsep(&saveptr, ":");
	char *gid = strsep(&saveptr, ":");
	char *gmem = strsep(&saveptr, ":");
	char *mem;
	struct group *g;

	g = malloc(sizeof(struct group));
	g->gr_name = malloc(GROUP_NAME_STR_SIZE);
	g->gr_passwd = malloc(GROUP_PASS_STR_SIZE);
	g->gr_mem = NULL;

	strncpy(g->gr_name, name, GROUP_NAME_STR_SIZE);
	strncpy(g->gr_passwd, passwd, GROUP_PASS_STR_SIZE);
	g->gr_gid = atoi(gid);

	if (!gmem)
		return g;

	g->gr_mem = malloc(GROUP_MEM_ARRAY_SIZE);
	bzero(g->gr_mem, GROUP_MEM_ARRAY_SIZE);
	for (i = 0; (mem = strtok_r(gmem, ",", &saveptr)) && i < GROUP_MEM_ARRAY_SIZE; i++) {
		gmem = NULL;
		g->gr_mem[i] = malloc(GROUP_NAME_STR_SIZE);
		strncpy(g->gr_mem[i], mem, GROUP_NAME_STR_SIZE);
	}

	return g;
}

static void _delete_passwd_struct(struct passwd *p)
{
	free(p->pw_name);
	free(p->pw_passwd);
	free(p->pw_gecos);
	free(p->pw_dir);
	free(p->pw_shell);

	free(p);
}

static void _delete_group_struct(struct group *g)
{
	int i;

	free(g->gr_name);
	free(g->gr_passwd);

	for (i = 0; g->gr_mem[i]; i++)
		free(g->gr_mem[i]);
	free(g->gr_mem);

	free(g);
}

static bool sb_shadow_passwd_init(void)
{
	int i;

	FILE* stream;
	FILE* (*_sb_fopen) (const char *, const char *) = get_dlsym("fopen", NULL);
	char* (*_sb_fgets) (char*, int, FILE*) = get_dlsym("fgets", NULL);
	int   (*_sb_fclose)(FILE*) = get_dlsym("fclose", NULL);

	char line[SB_SHADOW_LINE_BUFF_SIZE];
	char passwd_filename[PATH_MAX];

	snprintf(passwd_filename, PATH_MAX, "%s/etc/passwd", eroot);

	stream = _sb_fopen(passwd_filename, "r");
	if (!stream)
		return false;

	for (i = 0; _sb_fgets(line, SB_SHADOW_LINE_BUFF_SIZE, stream) && i < SB_SHADOW_MAX_USER; i++) {
		line[strcspn(line, "\n")] = 0;
		passwd_entries[i] = _new_passwd_struct(line);
	}

	_sb_fclose(stream);

	return true;
}

static bool sb_shadow_group_init(void)
{
	int i;

	FILE* stream;
	FILE* (*_sb_fopen) (const char *, const char *) = get_dlsym("fopen", NULL);
	char* (*_sb_fgets) (char*, int, FILE*) = get_dlsym("fgets", NULL);
	int   (*_sb_fclose)(FILE*) = get_dlsym("fclose", NULL);

	char group_filename[PATH_MAX];
	char line[SB_SHADOW_LINE_BUFF_SIZE];

	if(!_sb_fopen || !_sb_fgets || !_sb_fclose)
		return false;

	snprintf(group_filename, PATH_MAX, "%s/etc/group", eroot);

	stream = _sb_fopen(group_filename, "r");
	if (!stream)
		return false;

	for (i = 0; _sb_fgets(line, SB_SHADOW_LINE_BUFF_SIZE, stream) &&
	     i < SB_SHADOW_MAX_GROUP; i++) {
		line[strcspn(line, "\n")] = 0;
		group_entries[i] = _new_group_struct(line);
	}

	_sb_fclose(stream);

	return true;
}

static void _sb_shadow_passwd_clean(void)
{
	int i;

	for (i = 0; passwd_entries[i]; i++)
		_delete_passwd_struct(passwd_entries[i]);
}

static void _sb_shadow_group_clean(void)
{
	int i;

	for (i = 0; group_entries[i]; i++)
		_delete_group_struct(group_entries[i]);
}

void sb_shadow_init(void)
{
	eroot = getenv("EROOT");

	sb_shadow_real_getpwuid = get_dlsym("getpwuid", NULL);
	sb_shadow_real_getpwnam = get_dlsym("getpwnam", NULL);
	sb_shadow_real_getgrgid = get_dlsym("getgrgid", NULL);
	sb_shadow_real_getgrnam = get_dlsym("getgrnam", NULL);
	sb_shadow_real_getgrouplist = get_dlsym("getgrouplist", NULL);

	_sb_shadow_init = eroot != NULL && strncmp(eroot, "/", strlen(eroot)) != 0 &&
				sb_shadow_group_init() &&
				sb_shadow_passwd_init();
}

void sb_shadow_cleanup(void) {
    if(_sb_shadow_init) {
        _sb_shadow_passwd_clean();
        _sb_shadow_group_clean();
    }
}

static struct group *_hooked_getgrgid(gid_t gid)
{
	int i;

	for (i = 0; group_entries[i]; i++) {
		if (group_entries[i]->gr_gid == gid)
			return group_entries[i];
	}
	return NULL;
}

struct group *sb_shadow_getgrgid(gid_t gid) {
	return _sb_shadow_init ?
		_hooked_getgrgid(gid) :
		sb_shadow_real_getgrgid(gid);
}
default_symbol_version(sb_shadow_getgrgid, getgrgid, GLIBC_2.2.5);


static struct group *_hooked_getgrnam(const char *name)
{
	int i;

	for (i = 0; group_entries[i]; i++) {
		if (strcmp(group_entries[i]->gr_name, name) == 0)
			return group_entries[i];
	}
	return NULL;
}

struct group *sb_shadow_getgrnam(const char *name) {
	return _sb_shadow_init ?
		_hooked_getgrnam(name) :
		sb_shadow_real_getgrnam(name);
}
default_symbol_version(sb_shadow_getgrnam, getgrnam, GLIBC_2.2.5);


static int _hooked_getgrouplist(const char *user, gid_t group, gid_t *groups, int *ngroups)
{
	int i, j;
	int size = 0;

	groups[size++] = group;
	for (i = 0; group_entries[i]; i++) {
		for (j = 0; group_entries[i]->gr_mem && group_entries[i]->gr_mem[j]; j++) {
			if (strcmp(group_entries[i]->gr_mem[j], user) == 0) {
				groups[size++] = group_entries[i]->gr_gid;
				if (size >= *ngroups)
					return -1; // Please resize the buffer
			}
		}
	}
	*ngroups = size;
	return *ngroups;
}

int sb_shadow_getgrouplist(const char *user, gid_t group, gid_t *groups, int *ngroups) {
	return _sb_shadow_init ?
		_hooked_getgrouplist(user, group, groups, ngroups) :
		sb_shadow_real_getgrouplist(user, group, groups, ngroups);
}
default_symbol_version(sb_shadow_getgrouplist, getgrouplist, GLIBC_2.2.5);

static struct passwd *_hooked_getpwnam(const char *name) {
	int i;

	for (i = 0; passwd_entries[i]; i++) {
		if (strcmp(passwd_entries[i]->pw_name, name) == 0)
			return passwd_entries[i];
	}
	return NULL;
}

struct passwd *sb_shadow_getpwnam(const char *name)
{
	return _sb_shadow_init ?
		_hooked_getpwnam(name) :
		sb_shadow_real_getpwnam(name);
}
default_symbol_version(sb_shadow_getpwnam, getpwnam, GLIBC_2.2.5);

static struct passwd *_hooked_getpwuid(uid_t uid)
{
	int i;

	for (i = 0; passwd_entries[i]; i++) {
		if (passwd_entries[i]->pw_uid == uid)
			return passwd_entries[i];
	}
	return NULL;
}

struct passwd *sb_shadow_getpwuid(uid_t uid) {
	return _sb_shadow_init ?
		_hooked_getpwuid(uid) :
		sb_shadow_real_getpwuid(uid);
}
default_symbol_version(sb_shadow_getpwuid, getpwuid, GLIBC_2.2.5);
