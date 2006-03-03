#ifndef _CONTAIN_
#define _CONTAIN_
/* Containers */

/* Splay tree backed associative map
 *
 * This works by cheating at inheritance in C.  Create the structure you
 * care about and put the *first* member as being a "splay".  For instance:
 *
 * typedef struct {
 *   splay node;
 *   char *left;
 *   char *right;
 * } foo_t;
 *
 * Create the map with:
 *  foo_t *foomap=NULL;
 *
 * You will also need a comparitor.
 *  int foomapcmp(const foo_t *a, const foo_t *b)
 *  {
 *  	return strcmp(a->key,b->key);
 *  }
 *
 * Then to insert something into the map:
 *  foo_t node;
 *  node.key="a";
 *  node.value="apple";
 *  foomap=(foo_t *)splay_insert(
 *  	(splay*)foomap,
 *  	(splay_cmp_t)foomapcmp,
 *  	(splay*)node
 *  	);
 *
 * To search for something:
 *  struct foo_t node;
 *  node.key="a";
 *  foomap=(foo_t *)splay_find((splay*)foomap,
 *  	(splay_cmp_t)foomapcmp,
 *  	(splay*)node
 *  	);
 *  printf("%s is for %s\n",foomap->key,foomap->value);
 *
 * Note the annoyingly copious amount of casts, and the fact that the return
 * from splay_find is the top of the tree, and the result.
 */

typedef struct splay_node {
	struct splay_node *left;
	struct splay_node *right;
} splay;

typedef int (*splay_cmp_t)(const struct splay_node *, const struct splay_node *); 
typedef void (*visitor_t)(const splay *tree,void *userdata);

splay *splay_search_tree(splay *tree, splay_cmp_t cmp, splay *node);
splay *splay_delete(splay *tree, splay_cmp_t cmp, splay *node);
void   splay_purge(splay *tree);
splay *splay_insert(splay *tree, splay_cmp_t cmp, splay *node);
void splay_visit(const splay *tree, visitor_t pre,visitor_t inorder,visitor_t post,void *userdata);

/* 
 * Macros to wrap the splay tree to make it work a bit more like you expect.
 *
 * Map:
 * MAP_CREATE(alphabet,char *,strcmp,char *)
 * MAP_INSERT(alphabet,"a","apple")
 * printf("a is for %s",MAP_FIND(alphabet,"a")->value);
 *
 * Set:
 * SET_CREATE(afewofmyfavouritethings,char *,strcmp)
 * SET_INSERT(afewofmyfavouritethings,"raindrops on roses");
 * SET_INSERT(afewofmyfavouritethings,"whiskers on kittens");
 * if (SET_CONTAINS(afewofmyfaovuritethings,"whiskers on kittens")) {
 *   printf("I like whiskers on kittens\n");
 * } else {
 *   printf("Whiskers on kittens suck\n");
 * }
 *
 */

#define MAP_NODE(keytype,valuetype)					\
		struct {						\
			splay _map_node;				\
			keytype key;					\
			valuetype value;				\
		}

#define MAP(keytype,valuetype)						\
	struct {							\
		MAP_NODE(keytype,valuetype) *node;			\
		splay_cmp_t cmp;					\
	} 

#define MAP_INIT(cmp)							\
	{ NULL, (splay_cmp_t)cmp }					

#define CMP(name,keytype,exp)						\
	int name(splay *_map_a, splay *_map_b) { 			\
		struct _map_t {						\
			splay _map_node;				\
			keytype key;					\
		};							\
		keytype a = ((struct _map_t*)_map_a)->key;		\
		keytype b = ((struct _map_t*)_map_b)->key;		\
		return (exp);						\
	}
		
		

#define MAP_INSERT(name,vkey,vvalue) 					\
	do {								\
		typeof((name).node) _node=				\
				malloc(sizeof(typeof(*(name).node))); 	\
		*_node = (typeof(*(name).node)){{0,0},vkey,vvalue};	\
		(name).node=(typeof((name).node))splay_insert(		\
					(splay *)(name).node,		\
					(name).cmp,			\
					(splay *)_node			\
					); 				\
	} while(0);

#define MAP_FIND(name,vkey) 						\
	({								\
		typeof(*(name).node) _node;				\
	 	typeof((name).node) _ret;				\
		_node.key=vkey;						\
		(name).node=(typeof((name).node))splay_search_tree(	\
					(splay *)(name).node,		\
					(name).cmp,			\
					(splay *)&_node			\
					);				\
		if ((name).node 					\
		    && (name).cmp((splay*)(name).node,(splay*)&_node)==0)\
	 		_ret=(name).node;				\
	 	else							\
	 		_ret=NULL;					\
	 	_ret;							\
	 })

#define MAP_VISITOR(name,keytype,valuetype)				\
	void name(MAP_NODE(keytype,valuetype) *node,void *userdata)

#define MAP_VISIT(name,pre,inorder,post,userdata)			\
	splay_visit((splay*)(name).node,				\
			(visitor_t)pre,					\
			(visitor_t)inorder,				\
			(visitor_t)post,				\
			userdata)

/* Sets ****************************************************************/
#define SET_CREATE(name,keytype,cmp) \
	typedef struct { \
		splay node;						\
		keytype key;						\
	} name ## _t; 							\
	name ## _t *name = NULL; 					\
	int name ## _cmp(const splay *a,const splay *b) { 		\
		return cmp(((name ## _t*)a)->key,((name ## _t *)b)->key); \
	}

#define SET_INSERT(name,vkey) \
	do {				\
		name ## _t *_node=malloc(sizeof(name ## _t)); \
		_node->key=vkey;		\
		name=(name ##_t*)splay_insert((splay *)name,		\
					(splay_cmp_t)name ## _cmp,	\
					(splay *)_node			\
					); 				\
	} while(0);

#define SET_CONTAINS(name,vkey) \
	({								\
		name ## _t _node;					\
		_node.key=vkey;						\
		name=(name ##_t*)splay_search_tree(			\
					(splay *)name,			\
					(splay_cmp_t)name ## _cmp,	\
					(splay *)&_node			\
					);				\
	 	(name) && name ## _cmp((splay*)(name),(splay *)&_node)==0;\
	 })

#endif /* _CONTAIN_ */
