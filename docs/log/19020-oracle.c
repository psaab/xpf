/* Preserved source for the strongSwan oracle evidence in docs/log/19020.md. */
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
typedef struct { unsigned char *ptr; size_t len; } chunk_t;
typedef struct identification_t identification_t;
struct identification_t {
	chunk_t (*get_encoding)(identification_t *);
	int (*get_type)(identification_t *);
	unsigned (*hash)(identification_t *, unsigned);
	bool (*equals)(identification_t *, identification_t *);
	int (*matches)(identification_t *, identification_t *);
	bool (*contains_wildcards)(identification_t *);
	void *(*create_part_enumerator)(identification_t *);
	identification_t *(*clone)(identification_t *);
	void (*destroy)(identification_t *);
};
extern identification_t *identification_create_from_string_with_regex(char *);
extern identification_t *identification_create_from_string(char *);
extern bool library_init(char *settings, const char *namespace);
static void hex(chunk_t c) { for (size_t i = 0; i < c.len; i++) printf("%02x", c.ptr[i]); }
int main(void) {
	if (!library_init(NULL, "charon")) { fprintf(stderr, "library_init failed\n"); return 2; }
	char line[8192];
	while (fgets(line, sizeof line, stdin)) {
		line[strcspn(line, "\n")] = 0;
		char *tab = strchr(line, '\t'); if (!tab) continue; *tab = 0;
		/* side field: R = with_regex, P = plain */
		char *mode = strchr(tab+1, '\t');
		char side = 'P';
		char *b = tab + 1;
		if (mode) { *mode = 0; side = mode[1]; }
		char *a = line;
		identification_t *x = side=='R' ? identification_create_from_string_with_regex(a) : identification_create_from_string(a);
		identification_t *y = side=='R' ? identification_create_from_string_with_regex(b) : identification_create_from_string(b);
		if (!x || !y) { printf("NULL\tNULL\n"); if (x) x->destroy(x); if (y) y->destroy(y); continue; }
		printf("%d\t%d\t", x->get_type(x), y->get_type(y)); hex(x->get_encoding(x)); printf("\t"); hex(y->get_encoding(y));
		printf("\t%d\t%d\t%d\t%d\n", x->equals(x, y) ? 1 : 0, y->equals(y, x) ? 1 : 0, x->matches(x, y), y->matches(y, x));
		x->destroy(x); y->destroy(y);
	}
	return 0;
}
