/* originas.c
   read in a bgp dump file (or a concatenation of v4 and v6 dump files)
   stdin is a list of prefixes of the form prefix,<rest>
   stdout is a list of origin ASs preprended to the list e.g. AS234,advertisement,prefix,<rest>

   ./originas bgp4.yxy bgp6.txt <data.txt

*/

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "libavl.h"
#include <zlib.h>
#include <unistd.h>
#include <sys/types.h>
char *strcasestr(const char *haystack, const char *needle);

typedef __uint128_t u_int128_t ;

union v6add {
  u_int16_t sds[8];
  u_int32_t quad[4];
  u_int64_t lds[2];
  u_int128_t llds ;
  };

typedef union v6add v6addr ;


/* structure to hold each as path */

struct s_asp {
  char *aspth ;
  unsigned int *s_ases;
  int s_aspath_length ;
  struct s_asp *s_left ;
  struct s_asp *s_right ;
  } *s_asps = 0, *s_last = 0;

struct addr4 {
  u_int32_t  start ;
  u_int32_t end ;
  u_int32_t size ;
  u_int32_t origin_as ;
  struct addr4 *nxt ;
  struct addr4 *prv ;

  /* remove this */
  int flags ;
  char *address ;
  int mask ;
  int status ;
  } ;

struct addr6 {
  u_int128_t start ;
  u_int128_t end ;
  u_int128_t size ;
  u_int32_t origin_as ;
  struct addr6 *nxt ;
  struct addr6 *prv ;

  int flags ;
  char *address ;
  int mask ;
  int status ;
  } ;


struct as_names {
  unsigned int as ;
  char *asname ;
  } ;
 
int show_prefix = 0 ;
int use_names = 0 ;

avl_ptr addresses4 = 0 ;
avl_ptr addresses6 = 0 ;
avl_ptr asnames = 0 ;

extern void chop (char *);
extern int substr(char *, char *) ;
extern struct s_asp *parse_aspath();
extern void  print_addr(avl_ptr, FILE *, int);
extern void  print_addr6(avl_ptr, FILE *, int);
extern char *sprint6(u_int128_t *) ;
extern void process_prefix_list(char, int *, int, int);
extern void usage() ;
extern char *find_as(unsigned int) ;
extern int read_as_names(char *) ;

extern char *optarg;
extern int optind;
extern int optopt;
extern int opterr;
extern int optreset;


struct addr4 *aggregate4 = 0;
struct addr4 *v4head ;

struct addr6 *aggregate6 = 0;
struct addr6 *v6head ;

/*--------------------------------------------------
 * getas
 * get the next as number from the string <asp>
 * use the first AS in an AS set
 */

unsigned int
getas(char **asp)
{
  char *cp = *asp ;
  char *cpt, *cpp ;
  unsigned int asn ;

  if (!cp || !*cp) return(0) ;

  while ((*cp) && isspace(*cp)) ++cp ;
  if (!*cp) return(0) ;
  if (*cp == '{')  return(0) ;
  if (isdigit(*cp)) {
    if ((cpp = strchr(cp,' '))) 
      *cpp = '\0';
    asn = strtoul(cp,&cpt,10) ;
    if (*cpt == '.')
      asn = (asn << 16) + strtoul(++cpt,0,10) ;
    if (cpp) 
      *cpp = ' ' ;
    *asp = cpp ;
    return(asn) ;
    }
  return(0);
}


/*--------------------------------------------------
 * parse_aspath
 * create an aspath entry for announcement <p> using
 * aspath text <aspath>
 * strip out duplicate AS instances and private ASs
 */

struct s_asp *
parse_aspath(char *aspath)
{
  int i;
  int asl = 0;
  char *asp ;
  unsigned int new_aspath[260];
  unsigned int asn ;
  struct s_asp *sa = s_asps ;
  struct s_asp *parent = 0 ;

  /* if the path is the same as the last path then add this prefix in */
  if (s_last && !strcmp(s_last->aspth,aspath)) {
    return(s_last) ;
    }

  /* search all paths for this path */
  while ((sa) && (i = strcmp(sa->aspth,aspath))) {
    parent = sa ;
    if (i < 0) sa = sa->s_left ;
    else sa = sa->s_right ;
    }

  /* if this path is already in the list then add this ref */
  if (sa) return(sa) ;

  /* no - then set up a new path structure */
  sa = (struct s_asp *) malloc(sizeof *sa) ;

  /* copy the original path text to aspath array*/
  strcpy((sa->aspth = (char *) malloc(strlen(aspath) + 1)),aspath);
  asp = aspath ;
  while ((asn = getas(&asp))) {
    new_aspath[asl++] = asn;
    }

  sa->s_ases = (unsigned int *) malloc(asl * (sizeof asn)) ;
  for (i = 0 ; i < asl ; ++i) sa->s_ases[i] = new_aspath[i] ;
  sa->s_aspath_length = asl ;


  /* null pointers */
  sa->s_left = sa->s_right = 0 ;

  /* hoook into tree using full aspath */
  if (parent) {
    i = strcmp(parent->aspth,aspath);
    if (i < 0) parent->s_left = sa ;
    else parent->s_right = sa ;
    }
  else s_asps = sa ;

  s_last = sa ;
  return(sa) ;
}



/*--------------------------------------------------
 * addr_cmp
 * compare a stored prefix with a start address and prefix length
 * return -1 if less, 0 if eql and 1 if gtr
 */

int 
addr4_cmp(avl_ptr adp1, avl_ptr adp2)
{
  if (((struct addr4 *)adp1->payload)->start < ((struct addr4 *)adp2->payload)->start) return(-1) ;
  if (((struct addr4 *)adp1->payload)->start > ((struct addr4 *)adp2->payload)->start) return(1) ;
  if (((struct addr4 *)adp1->payload)->size >  ((struct addr4 *)adp2->payload)->size) return(-1) ;
  if (((struct addr4 *)adp1->payload)->size <  ((struct addr4 *)adp2->payload)->size) return(1) ;
  return(0) ;
}

int 
addr6_cmp(avl_ptr adp1, avl_ptr adp2)
{
  if (((struct addr6 *)adp1->payload)->start < ((struct addr6 *)adp2->payload)->start) return(-1) ;
  if (((struct addr6 *)adp1->payload)->start > ((struct addr6 *)adp2->payload)->start) return(1) ;
  if (((struct addr6 *)adp1->payload)->size >  ((struct addr6 *)adp2->payload)->size) return(-1) ;
  if (((struct addr6 *)adp1->payload)->size <  ((struct addr6 *)adp2->payload)->size) return(1) ;
  return(0) ;
}

int 
addr4_find(avl_ptr adp1, avl_ptr adp2)
{
  if (((struct addr4 *)adp1->payload)->start < ((struct addr4 *)adp2->payload)->start) return(-1) ;
  if (((struct addr4 *)adp1->payload)->start > ((struct addr4 *)adp2->payload)->end) return(1) ;
  return(0) ;
}

int 
addr6_find(avl_ptr adp1, avl_ptr adp2)
{
  if (((struct addr6 *)adp1->payload)->start < ((struct addr6 *)adp2->payload)->start) return(-1) ;
  if (((struct addr6 *)adp1->payload)->start > ((struct addr6 *)adp2->payload)->end) return(1) ;
  return(0) ;
}

int 
asn_cmp(avl_ptr adp1, avl_ptr adp2)
{
  if (((struct as_names *)adp1->payload)->as < ((struct as_names *)adp2->payload)->as) return(-1) ;
  if (((struct as_names *)adp1->payload)->as > ((struct as_names *)adp2->payload)->as) return(1) ;
  return(0) ;
}
/*---------------------------------------------------*/


char *
find_as(unsigned int asn)
{
  struct avldata local ;
  struct as_names sasn ;
  avl_ptr find ;

  local.payload = &sasn ;
  sasn.as = asn ;
  if ((find = avlaccess(asnames,&local,asn_cmp))) 
    return(((struct as_names *)find->payload)->asname) ;
  return(NULL) ;
}

char *
n4ta(u_int32_t *t, int mask)
{
  char *ts ;
  unsigned int q[4] ;
  q[0] = ((*t) >> 24) & 255 ;
  q[1] = ((*t) >> 16) & 255 ;
  q[2] = ((*t) >>  8) & 255 ;
  q[3] = (*t) & 255 ;
  ts = (char *) malloc(25) ;
  if (mask > 0) {
    sprintf(ts,"%u.%u.%u.%u/%d",q[0],q[1],q[2],q[3],mask) ;
    }
  else {
    sprintf(ts,"%u.%u.%u.%u",q[0],q[1],q[2],q[3]) ;
    }
  return(ts);
}

char *
n6ta(u_int128_t *t, int mask)
{
  v6addr lcl ;
  int i ;
  int tmp ;
  int zero = 0 ;
  char *cp ;
  int ii[8] = {7,6,5,4,3,2,1,0} ;
  static char buff[256] ;
  char *ts ;

  lcl.llds = *t ;
  cp = buff;
  for (i = 0 ; i < 8 ; ++i) {
    if ((i < 7) && (zero == 0) && (lcl.sds[ii[i]] == 0) && (lcl.sds[ii[i+1]] == 0)) {
      sprintf(cp,":") ;
      if (!i) strcat(cp,":") ;
      zero = 1 ;
      }
    else if ((zero == 1) && (lcl.sds[ii[i]] == 0)) {
      zero = 1 ;
      }
    else if (i < 7) {
      sprintf(cp,"%x:",lcl.sds[ii[i]]);
      if (zero) { ++zero; } 
      }
    else {
      sprintf(cp,"%x",lcl.sds[ii[i]]);
      }
    cp += strlen(cp) ;
    }
  if (mask > 0) {
    sprintf(cp,"/%d",mask) ;
    }
  ts = strdup(buff) ;
  return(ts);
}


struct addr4 *
address4_insert(avl_ref addresses,u_int32_t *start, u_int32_t *size,int mask)
{
  struct avldata local;
  struct addr4 address ;
  struct addr4 *ap = 0;
  avl_ptr tmp ;

  local.payload = &address ;
  address.start = *start;
  address.end = *start + *size - 1 ;
  address.size = *size ;

  avlinserted = 0 ;
  avlinsert(addresses,&local,addr4_cmp) ;
  tmp = avl_inserted ;
  if (avlinserted) {
    ap = (struct addr4 *) malloc(sizeof *ap) ;
    ap->start = address.start ;
    ap->end = address.end ;
    ap->size = address.size ;
    ap->origin_as = 0 ;
    ap->nxt = 0 ;
    ap->prv = 0 ;

    ap->flags = 0 ;
    if (mask) {
      ap->address= n4ta(&(ap->start),mask) ;
      ap->mask = mask ;
      }
    ap->status = 1 ;

    tmp->payload = ap ;
    }
  return(ap) ;
}

struct addr6 *
address6_insert(avl_ref addresses,u_int128_t *start, u_int128_t *size, int mask)
{
  struct avldata local;
  struct addr6 address ;
  struct addr6 *ap = 0;
  avl_ptr tmp ;

  local.payload = &address ;
  address.start = *start;
  address.end = address.start ;
  address.end += *size ;
  address.end  -= 1 ;
  address.size = *size ;

  avlinserted = 0 ;
  avlinsert(addresses,&local,addr6_cmp) ;
  tmp = avl_inserted ;
  if (avlinserted) {
    ap = (struct addr6 *) malloc(sizeof *ap) ;
    ap->start = address.start ;
    ap->end = address.end ;
    ap->size = address.size ;
    ap->origin_as = 0 ;
    ap->nxt = 0 ;
    ap->prv = 0 ;

    ap->flags = 0 ;
    if (mask) {
      ap->address= n6ta(&(ap->start), mask) ;
      ap->mask = mask ;
      }
    ap->status = 1 ;

    tmp->payload = ap ;
    }
  return(ap) ;
}


unsigned int
find6_origin_as(u_int128_t *start,char **p)
{
  struct avldata local;
  struct addr6 address ;
  struct addr6 *ap;
  avl_ptr tmp ;

  local.payload = &address ;
  address.start = *start;
  address.end = *start;
  address.size = 1 ;

  if ((tmp = avlaccess(addresses6,&local,addr6_find))) {
    *p = ((struct addr6 *)tmp->payload)->address ;
    return(((struct addr6 *)tmp->payload)->origin_as) ;
    }
  return(0) ;
}

unsigned int
find4_origin_as(u_int32_t *start,char **p)
{
  struct avldata local;
  struct addr4 address ;
  struct addr4 *ap;
  avl_ptr tmp ;

  local.payload = &address ;
  address.start = *start;
  address.end = *start;
  address.size = 1 ;

  if ((tmp = avlaccess(addresses4,&local,addr4_find))) {
    *p = ((struct addr4 *)tmp->payload)->address ;
    return(((struct addr4 *)tmp->payload)->origin_as) ;
    }
  return(0) ;
}


/*--------------------------------------------------
 * add_addr
 * add address <addr> with aspath <asp> to the list of prefixes and as paths
 * if its not a selected prefix then simply add the as path to the as path set
 * return TRUE if it parses correctly
 */

int
add_addr(char *addr, char *asp)
{
  int i ;
  int q[4];
  int mask;
  int msk ;
  v6addr ss ;
  u_int128_t size;
  int pv = 2;
  u_int128_t strt ;
  unsigned int ed ;
  char *cp ;
  struct addr4 *aptr ;
  struct addr6 *aptr6 ;
  struct s_asp *sa ;
  u_int32_t strt4 ;
  u_int32_t size4 ;

  if (strchr(addr,':')) {
    // V6 address processing
    unsigned long int hex[8] ;
    v6addr x ;
    char *cp ;
    char *slashcp ;
    int i ;
    int k ;
    int shuffle = 8 ;
    u_int128_t start ;

    slashcp = strchr(addr,'/') ;
    if (sscanf(slashcp,"/%d",&mask) != 1) return(0) ;
    msk = mask ;
    if (msk > 64) {
      ss.lds[1] = 0 ;
      msk -= 64 ;
      if (msk > 32) {
        ss.quad[1] = 0 ;
        msk -= 32 ;
        ss.quad[0] = (1 << (32 - msk)) ;
        }
      else {
        ss.quad[0] = 0 ; 
        ss.quad[1] = (1 << (32 - msk)) ;
        }
      }
    else {
      ss.lds[0] = 0 ;
      if (msk > 32) {
        msk -= 32 ;
	ss.quad[2] = (1 << (32 - msk)) ;
        ss.quad[3] = 0 ;
        }
      else {
        ss.quad[2] = 0 ;
        ss.quad[3] = (1 << (32 - msk)) ;
        }
      }
    size = ss.llds ;
    *slashcp = ':';
    for (i = 0 ; i < 8 ; ++i) hex[i] = 0 ;
    i = 0 ;
    cp = addr ;
    while (cp) {
      if (sscanf(cp,"%lx:",&hex[i]) != 1) return(0) ;
      if ((cp = strchr(cp,':')))
        ++cp ;
      ++i ;
      if (cp && (*cp == ':')) { 
        if (shuffle < 8) return(0) ;
        shuffle = i ;
        ++cp ;
        if (*cp == ':') 
          cp = 0 ;
        }
      if (i == 8) continue;
      }
    *slashcp = '/' ;
    if (shuffle < 8) {
      k = 7 ;
      while (i > shuffle) {
        hex[k] = hex[i-1] ;
        hex[i-1] = 0 ;
        --k ;
        --i ;
        }
      }

    for (i = 0 ; i < 8 ; ++i) { 
      x.sds[7 - i] = hex[i] ;
      }
    start = x.llds ;

    if ((!x.lds[0]) && (!x.lds[1])) return(1) ;
    sa = parse_aspath(asp);

    aptr6 = address6_insert(&addresses6,&start,&size,mask);
    aptr6->origin_as = sa->s_ases[sa->s_aspath_length - 1] ;
    return(1) ;
    }
  /* address does not start with a digit - error */
  if (!isdigit(*addr)) {
    return(0);
    }

  /* Break address into octets and mask. If no explicit mask
     then apply the class A/B/C rules */
  i = sscanf(addr,"%d.%d.%d.%d/%d", &q[0], &q[1], &q[2], &q[3] ,&msk);
  if (i < 5) {
    if (q[0] < 128) msk = 8 ;
    else if (q[0] < 192) msk = 16 ;
    else msk = 24 ;
    strcpy((cp = (char *)malloc(strlen(addr) + 4)), addr) ;
    addr = cp ;
    cp = addr + strlen(addr) ;
    sprintf(cp,"/%d",msk);
    }

  /* get start and end 32-bit address values of the address span */
  strt4 = (q[0] << 24) + (q[1] << 16) + (q[2] << 8) + q[3];
  if (!strt) {
    /* this is the default route - in this case its not much use, so it's rejected, but not with an error value */
    return(1) ;
    }

  size4 = 1 << (32 - msk) ;
  sa = parse_aspath(asp);
  if (!(sa->s_aspath_length)) return(1) ;
  aptr = address4_insert(&addresses4,&strt4,&size4,msk);
  aptr->origin_as = sa->s_ases[sa->s_aspath_length - 1] ;
  return(1) ;
}


/*--------------------------------------------------
 * chop
 * remove trailing aspath detritus from the aspath string
 */

void
chop(char *s)
{
  int i = strlen(s) - 1 ;

  while ((i >= 0)
          && (isspace(s[i]) ||
              (s[i] == '\n') ||
              (s[i] == '\r') ||
              (s[i] == 'i') ||
              (s[i] == 'e') ||
              (s[i] == '?'))) {
    s[i--] = '\0';
    }
}


/*--------------------------------------------------
 * substr
 * return TRUE is s1 is a substring of s2
 */

int substr(char *s1, char *s2)
  {
  int l = strlen(s1);

  while ((s2 = strchr(s2, *s1))) {
    if (!strncmp(s1,s2,l)) return(1) ;
    if (!*(++s2)) return(0) ;
    }
  return(0) ;
  }

char sv6[40] ;

char *
sprint6(u_int128_t *a)
{
  char * cp ;

  cp = n6ta(a,0) ;
  strcpy(sv6,cp) ;
  free(cp) ;
  return(sv6) ;
}

unsigned int
originas(char *f, char **p)
{
  v6addr x ;
  unsigned int q[4] ;
  unsigned int msk ;
  unsigned int mask ;
  unsigned int as  = 0 ;
  unsigned int address ;
  int i ;
  char *cp ;
  char *cp1 ;
  unsigned long int hex[8] ;
  int k ;
  int shuffle = 8 ;
  u_int128_t start ;
  u_int32_t strt ;
  int lmsk ;
  unsigned long int lmask ;
  static char prefix_str[1024] ;
  
  if ((cp1 = strchr(f,':'))) {
    if ((cp1 = strchr(f,'/'))) {
      if (sscanf(cp1,"/%d",&msk) != 1) return(0) ;
      *cp1 = ':';
      }
    for (i = 0 ; i < 8 ; ++i) hex[i] = 0 ;
    i = 0 ;
    cp = f ;
    while ((cp) && (*cp)) {
      if (sscanf(cp,"%lx",&hex[i]) != 1) { cp = 0 ; return(0) ; }
      if ((cp = strchr(cp,':'))) ++cp ;
      ++i ;
      if (cp && (*cp == ':')) { 
        if (shuffle < 8) return(0) ;
        shuffle = i ;
        ++cp ;
        if (*cp == ':')  cp = 0 ;
        }
      if (i > 8) return(0);
      }
    if (cp1) *cp1 = '/' ;
    if (shuffle < 8) {
      k = 7 ;
      while (i > shuffle) {
        hex[k] = hex[i-1] ;
        hex[i-1] = 0 ;
        --k ;
        --i ;
        }
      }
    x.lds[1] = ((hex[0] & 65535) << 48) + ((hex[1] & 65535) << 32)  + 
        ((hex[2] & 65535) << 16) + (hex[3] & 65535) ;
    x.lds[0] = ((hex[4] & 65535) << 48) + ((hex[5] & 65535) << 32)  + 
        ((hex[6] & 65535) << 16) + (hex[7] & 65535) ;
    start = x.llds ;
    if (start == 0) return(0) ;

    //    printf("line <%s>, searching for %s\n",f,n6ta(&start)) ;

    as = find6_origin_as(&start,p) ;
    return(as) ;
    }
  else if ((cp1 = strchr(f,'.'))) {
    i = sscanf(f,"%d.%d.%d.%d/%d", &q[0], &q[1], &q[2], &q[3] ,&msk);
    if (i < 4) return(0) ;
    if (i < 5) msk = 24 ;
    strt = ((q[0] & 255) << 24) + ((q[1] & 255) << 16) + ((q[2] & 255) << 8) + (q[3] & 255) ;
    as = 0 ;
    as = find4_origin_as(&strt,p) ;
    return(as);
    }
  else if (isdigit(*f)) {
    return(strtoul(f,0,10)) ;
    }
  else if ((toupper(*f) == 'A') && (toupper(*(f+1)) == 'S') && isdigit(*(f+2))) {
    return(strtoul(f+2,0,10)) ;
    }
  return(0) ;
  }

void
process_prefix_list(char delim, int *f, int fl, int showp)
{
  char *inl ;
  char inll[1026] ;
  char *vec[256] ;
  unsigned int asvec[256] ;
  int vec_len ;
  int fi ;
  int vi ;
  char sav ;
  char *cp ;
  char *pfx ;
  char *prefixes[256] ;
  char *asname ;

  inl =&inll[0] ;
  *inl++ = ',';
  
  while (fgets(inl,1024,stdin)) {
    if ((cp = strchr(inl,'\n'))) *cp = '\0';
    if ((cp = strchr(inl,'\r'))) *cp = '\0';
    printf("%s",inl) ;
    vec_len = 1 ;
    vec[vec_len] = inll ;
    cp  = inll ;
    ++cp ;
    while ((vec_len < 255) && (cp = strchr(cp,delim))) {
      vec[++vec_len] = cp++ ;
      }      
    fi = 0 ;
    vi = 0 ;
    while (fi < fl) {
      asvec[vi] = 0 ;
      prefixes[vi] = 0 ;
      if ((f[fi] <= vec_len) && (vec[f[fi]]) && (*(vec[f[fi]] + 1) != delim)) {
        if (f[fi] < vec_len) {
          sav = *(vec[f[fi] + 1]) ;
          *(vec[f[fi]+1]) = '\0';
          }
        if ((asvec[vi] = originas(vec[f[fi]]+1,&pfx))) {
          if (showp) prefixes[vi] = strdup(pfx) ;
	  }
        else if (showp) prefixes[vi] = "" ;

        if (use_names) {
          asname = find_as(asvec[vi]) ;
          if (asname) {
            printf("%c%s",delim,asname) ;
	    }
          else {
            printf("%cAS%u",delim,asvec[vi]) ;
	    }
	  }
        else
          printf("%c%u",delim,asvec[vi]) ;
        if (f[fi] < vec_len) {
          *(vec[f[fi]+1]) = sav;
          }
        }
      else {
        printf("%c%u",delim,0) ;
        }    
      ++fi ;
      ++vi ;
      }
    if (showp) {
      fi = 0 ;
      while (fi < fl) {
        if (prefixes[fi] && (*(prefixes[fi]))) { printf("%c%s",delim,prefixes[fi]) ; free(prefixes[fi]) ; }
        else { printf("%c",delim) ; }
	++fi ;
        }
      }
    printf("\n") ;
    fflush(stdout) ;
    }
  }



char pbuffer[256] ;

char *
print_v4_addr(struct addr4 *p)
{
  u_int32_t t ;
  unsigned int q[4] ;
  unsigned int asn ;
  char ts[256] ;
  char te[256] ;
  char tz[24] ; 
  
  t = p->start ;
  q[0] = (t >> 24) & 255 ;
  q[1] = (t >> 16) & 255 ;
  q[2] = (t >>  8) & 255 ;
  q[3] = t & 255 ;
  sprintf(ts,"%u.%u.%u.%u",q[0],q[1],q[2],q[3]) ;

  t = p->end ;
  q[0] = (t >> 24) & 255 ;
  q[1] = (t >> 16) & 255 ;
  q[2] = (t >>  8) & 255 ;
  q[3] = t & 255 ;
  sprintf(te,"%u.%u.%u.%u",q[0],q[1],q[2],q[3]) ;
  asn = p->origin_as ;
  q[3] = (unsigned int) p->size ;
  sprintf(tz,"(%u)",q[3]) ;
  sprintf(pbuffer,"%s - %s AS%u %s",ts,te,asn,tz) ;

  return(pbuffer) ;
} 


void 
print_addr4(avl_ptr adp, FILE *param, int depth)
{
  struct addr4 *ap ;
  unsigned int q[4] ;
  unsigned int size ;

  ap = (struct addr4 *) adp->payload ;
  printf("%s\n",print_v4_addr(ap)) ;
}

void 
print_addr4_x(avl_ptr adp, FILE *param, int depth)
{
  struct addr4 *ap ;
  unsigned int q[4] ;
  unsigned int size ;

  ap = (struct addr4 *) adp->payload ;
  printf("%s\n",print_v4_addr(ap)) ;
}

void 
print_addr6(avl_ptr adp, FILE *param, int depth)
{
  struct addr6 *ap ;

  ap = (struct addr6 *) adp->payload ;
  printf("AS%d %s - ",ap->origin_as,sprint6(&(ap->start))) ;
  printf("%s\n",sprint6(&ap->end)) ;
} 

void 
deaggregate4()
{
  struct addr4 *ap, *t, *xn, *xp, *app, *apnxt ;
  u_int32_t start, end, size ;
  struct avldata local;
  struct addr4 address ;
  enum AVLRES tmp ;

 
  local.payload = &address ;
  ap = v4head ;
  while (ap) {
    app = 0 ;
    if (ap->nxt) {
      if (ap->end >= ap->nxt->start) {
        if (ap->start < ap->nxt->start) {
          /* shrink this to the leading part that is "exposed" */
          /* record the overhang */
          end = ap->end ;
          size = end - start + 1 ;

          /* now shrink this */
          ap->end = ap->nxt->start - 1 ; 
          ap->size = ap->end - ap->start + 1 ;

          /* if there is "overhang" then find the corect insert place for the overhang, which is proir to the
	  next entry with start >= the start of this remainder start */
          if (end > ap->nxt->end) {
            /* now generate a new item with start ap->nxt->end + 1 through to ap->end */
            start = ap->nxt->end  + 1 ;
            size = end - start + 1 ;
            if (size > 0) {
              if ((t = address4_insert(&addresses4,&start,&size,0))) {
                if (avlinserted) {
                  t->origin_as = ap->origin_as ;
                  t->flags = 0 ;
                  t->status = 2 ;
                  t->address = ap->address ;
                  t->mask = ap->mask ;
                  xn = ap->nxt ;
                  xp = xn->prv ;
                  while ((xn) && ((xn->start < t->start) || ((xn->start == t->start) && (xn->size > t->size)))) { xp = xn ; xn = xn->nxt ; }
                  t->prv = xp ;
                  if (xp) xp->nxt = t ;
                  t->nxt = xn ;
                  if (xn) xn->prv = t ;
		  }
	        }
	      }
            }
          }
        else if (ap->start == ap->nxt->start) {
          /* there is no leading part */
          /* remove ap from the linked list */
          char *addr ;

          addr = ap->address ;
          ap->status += 10 ;
	  ap->nxt->prv = ap->prv ;
          if (ap->prv) ap->prv->nxt = ap->nxt ;
          else v4head = ap->nxt ;
          end = ap->end ;

          address.start = ap->start;
          address.end = ap->end ;
          address.size = ap->size ;
          tmp = avlremove(&addresses4,&local,addr4_cmp) ;
          if (tmp == ERROR) {
            printf("Remove Error!\n") ;
	    }
          else {
            app = ap ;
	    }

          /* if there is "overhang" then find the corect insert place for the overhang, which is proir to the
	  next entry with start >= the start of this remainder start */
          if (end > ap->nxt->end) {
            /* now generate a new item with start ap->nxt->end + 1 through to ap->end */
            start = ap->nxt->end  + 1 ;
            size = end - start + 1 ;
            if (size > 0) {
              if ((t = address4_insert(&addresses4,&start,&size,0))) {
                if (avlinserted) {
                  t->origin_as = ap->origin_as ;
                  t->flags = 0 ;
                  t->status = 2 ;
                  t->address = addr ;
                  t->mask = ap->mask ;
                  xn = ap->nxt ;
                  xp = xn->prv ;
                  while ((xn) && ((xn->start < t->start) || ((xn->start == t->start) && (xn->size > t->size)))) { xp = xn ; xn = xn->nxt ; }
                  t->prv = xp ;
                  if (xp) xp->nxt = t ;
                  t->nxt = xn ;
                  if (xn) xn->prv = t ;
		  }
	        }
	      }
            }
	  }
        }
      }
    ap = ap->nxt ;
    if (app) { 
      free(app) ; 
      app = 0 ; 
      }
    }

  
  if (!show_prefix) {
    ap = v4head ;
    while (ap && ap->nxt) {
      if ((ap->end +1 == ap->nxt->start) && (ap->origin_as == ap->nxt->origin_as)) {
        app = ap->nxt ;
        size = ap->size + app->size ;
        end = app->end ;
        apnxt = app->nxt ;

        address.start = app->start;
        address.end = app->end ;
        address.size = app->size ;
        tmp = avlremove(&addresses4,&local,addr4_cmp) ;
        if (tmp == ERROR) {
          printf("Remove Error!\n") ;
	  }
        else {
          free(app) ;
	  }
      
        ap->size = size ;
        ap->end = end ;
        ap->nxt = apnxt ;
        if (apnxt) apnxt->prv = ap ;
        }
      else {
        ap = ap->nxt ;
        }
      }
    }
}


void 
deaggregate6()
{
  struct addr6 *ap, *t, *xn, *xp, *app, *apnxt ;
  u_int128_t start, end, size ;
  struct avldata local;
  struct addr6 address ;
  enum AVLRES tmp ;

 
  local.payload = &address ;
  ap = v6head ;
  while (ap) {
    app = 0 ;
    if (ap->nxt) {
      if (ap->end >= ap->nxt->start) {
        if (ap->start < ap->nxt->start) {
          /* shrink this to the leading part that is "exposed" */
          /* record the overhang */
          end = ap->end ;
          size = end ;
          size -= start ;
          size += 1 ;

          /* now shrink this */
          ap->end = ap->nxt->start - 1 ; 
          ap->size = ap->end - ap->start + 1 ;

          /* if there is "overhang" then find the corect insert place for the overhang, which is proir to the
	  next entry with start >= the start of this remainder start */
          if (end > ap->nxt->end) {
            /* now generate a new item with start ap->nxt->end + 1 through to ap->end */
            start = ap->nxt->end  ;
            start += 1 ;
            size = end ;
            size  -= start ;
            size += 1 ;
            if (size > 0) {
              if ((t = address6_insert(&addresses6,&start,&size,0))) {
                if (avlinserted) {
                  t->origin_as = ap->origin_as ;
                  t->flags = 0 ;
                  t->status = 2 ;
                  t->address = ap->address ;
                  t->mask = ap->mask ;
                  xn = ap->nxt ;
                  xp = xn->prv ;
                  while ((xn) && ((xn->start < t->start) || ((xn->start == t->start) && (xn->size > t->size)))) { xp = xn ; xn = xn->nxt ; }
                  t->prv = xp ;
                  if (xp) xp->nxt = t ;
                  t->nxt = xn ;
                  if (xn) xn->prv = t ;
		  }
	        }
	      }
            }
          }
        else if (ap->start == ap->nxt->start) {
          /* there is no leading part */
          /* remove ap from the linked list */
          ap->status += 10 ;
	  ap->nxt->prv = ap->prv ;
          if (ap->prv) ap->prv->nxt = ap->nxt ;
          else v6head = ap->nxt ;
          end = ap->end ;

          address.start = ap->start;
          address.end = ap->end ;
          address.size = ap->size ;
          tmp = avlremove(&addresses6,&local,addr6_cmp) ;
          if (tmp == ERROR) {
            printf("Remove Error 6!\n") ;
	    }
          else {
            app = ap ;
	    }

          /* if there is "overhang" then find the corect insert place for the overhang, which is proir to the
	  next entry with start >= the start of this remainder start */
          if (end > ap->nxt->end) {
            /* now generate a new item with start ap->nxt->end + 1 through to ap->end */
            start = ap->nxt->end  + 1 ;
            size = end - start + 1 ;
            if (size > 0) {
              if ((t = address6_insert(&addresses6,&start,&size,0))) {
                if (avlinserted) {
                  t->origin_as = ap->origin_as ;
                  t->flags = 0 ;
                  t->status = 2 ;
                  t->address = ap->address ;
                  t->mask = ap->mask ;
                  xn = ap->nxt ;
                  xp = xn->prv ;
                  while ((xn) && ((xn->start < t->start) || ((xn->start == t->start) && (xn->size > t->size)))) { xp = xn ; xn = xn->nxt ; }
                  t->prv = xp ;
                  if (xp) xp->nxt = t ;
                  t->nxt = xn ;
                  if (xn) xn->prv = t ;
		  }
	        }
	      }
            }
	  }
        }
      }
    ap = ap->nxt ;
    if (app) { 
      free(app) ; 
      app = 0 ; 
      }
    }

  if (!show_prefix) {
    ap = v6head ;
    while (ap && ap->nxt) {
      if ((ap->end +1 == ap->nxt->start) && (ap->origin_as == ap->nxt->origin_as)) {
        app = ap->nxt ;
        size = ap->size ;
        size += app->size ;
        end = app->end ;
        apnxt = app->nxt ;

        address.start = app->start;
        address.end = app->end ;
        address.size = app->size ;
        tmp = avlremove(&addresses6,&local,addr6_cmp) ;
        if (tmp == ERROR) {
          printf("Remove Error 61!\n") ;
  	  }
        else {
          free(app) ;
	  }
      
        ap->size = size ;
        ap->end = end ;
        ap->nxt = apnxt ;
        if (apnxt) apnxt->prv = ap ;
        }
      else {
        ap = ap->nxt ;
        }
      }
    }
}


void 
link4(avl_ptr adp, FILE *param, int depth)
{
  struct addr4 *ap ;

  ap = (struct addr4 *) adp->payload ;
  ap->prv = aggregate4 ;
  if (!v4head) { v4head = ap ; aggregate4 = ap ; }
  else { aggregate4->nxt = ap ; }
  ap->nxt = 0 ;
  ap->flags = 0 ;
  aggregate4 = ap ;
}


void 
link6(avl_ptr adp, FILE *param, int depth)
{
  struct addr6 *ap ;

  ap = (struct addr6 *) adp->payload ;
  ap->prv = aggregate6 ;
  if (!v6head) { v6head = ap ; aggregate6 = ap ; }
  else { aggregate6->nxt = ap ; }
  ap->nxt = 0 ;
  ap->flags = 0 ;
  aggregate6 = ap ;
}


int
read_as_names(char *fname) {
  FILE *f ;
  char buffer[1024] ;
  unsigned int asn, ash, asl ;
  char *name ;
  char *cp ;
  struct avldata local ;
  struct as_names sasn ;
  struct as_names *sasnp ;
  avl_ptr tmp ;

  local.payload = &sasn ;
  if (!(f = fopen(fname,"r"))) return(0) ;
  while (fgets(buffer,1023,f)) {
    buffer[strlen(buffer) - 1] = '\0';
    if (*buffer == '#') continue ;
    
    if ((cp = strchr(buffer,'\t'))) {
      name = (cp + 1) ;
      *cp = '\0'; ;
      }
    else if ((cp = strchr(buffer,' '))) {
      name = &buffer[8] ;
      *cp = '\0'; ;
      }
    if (strchr(buffer,'.')) {
      sscanf(buffer,"%d.%d",&ash,&asl) ;
      asn = (ash << 16) + asl ;
      }
    else
      asn = strtoul(buffer,0,10) ;

    sasn.as = asn ;
    avl_inserted = 0 ;
    avlinsert(&asnames,&local,asn_cmp) ;
    tmp = avl_inserted ;
    if (avlinserted) {
      sasnp = (struct as_names *) malloc(sizeof *sasnp) ;
      sasnp->as = asn ;
      sasnp->asname = strdup(name) ;
      tmp->payload = sasnp ;
      }
    }
  fclose(f) ;
  return(1) ;
}

/*--------------------------------------------------------------------------------------------------*/

/*
 * read dumpfile
 */

int
read_dump(char *filename) 
{
  FILE *fi ;
  gzFile gfi ;
  char inl[1025] ;
  char pnl[1025] ;
  char lastaddr[128] = "" ;
  char *addr ;
  char *aspath ;
  char *cp ;
  int parse_header = 0 ;
  int pathoffset ;
  int use_gz = 0 ;
  char *rdf = "1" ;
  char *pdf ;

  if (strcasestr(filename, ".gz") != (char *)NULL) {
    if (!(gfi = gzopen(filename,"r"))) return(0) ;
    use_gz = 1 ;
    }
  else {
    if (!(fi = fopen(filename,"r"))) return(0) ;
    }
  
  while (rdf && (parse_header < 2)) {
    if (use_gz) {
      rdf = gzgets(gfi,inl,1024) ;
      }
    else {
      rdf = fgets(inl,1024,fi) ;
      }
    if (!rdf) continue ;
    if (parse_header) {

      //the last line of the header is
      // "Network..Next Hop..Metric LocPrf Weight Path"

      if (substr("Prf",inl)) parse_header = 0 ;
      continue ;
      }

    // if there is a header it starts with "show ip bgp"
    if (!strncmp(inl,"show",4)) {
      parse_header = 1 ;
      continue ;
      }

    // look for lines where the address is too long and the
    // path field is offset
    pathoffset = 0 ;
    while (!isspace(inl[19 + pathoffset])) ++pathoffset ;

    addr = &inl[3] ;
    if ((cp = strchr(addr,' '))) *cp++ =  '\0';
    chop(addr) ;

    // a blank line means use the last address 
    if (!*addr) { 
      strcpy(addr,lastaddr) ; 
      cp = addr + strlen(addr) + 1 ; 
      } 
    strcpy(lastaddr,addr) ;

    if (strchr(addr,':')) {
      if (!cp || (strlen(cp) < 35)) {
        if (use_gz) {
          pdf = gzgets(gfi,pnl,1024) ;
          }
        else {
          pdf = fgets(pnl,1024,fi) ;
          }
        cp = pnl ;
   
        if (strlen(cp) < 60) {
          if (use_gz) {
            pdf = gzgets(gfi,pnl,1024) ;
            }
          else {
            pdf = fgets(pnl,1024,fi) ;
            }
          }
        aspath = &pnl[61] ;
        }
      else {
        aspath = &inl[61] ;
        }
      if (*aspath == 'i') continue ;
      }
    else 
      aspath = &inl[61 + pathoffset] ;

    // look for the "best" (or selected) as path
    if ((inl[1] != '>') || !*addr) continue ;
    
    chop(aspath) ;
    add_addr(addr,aspath) ;
    }
  if (use_gz) { gzclose(gfi) ; }
  else { fclose(fi) ; }
  return(1) ;
}


/*--------------------------------------------------------------------------------------------------*/

/*
 * usage
 */
 
void
usage() {
  printf("Usage: originas [-f fields] [-d delimiter]\n   originas -d , -f 2,3\n");
  exit(1) ;
  }
  
/*--------------------------------------------------------------------------------------------------*/

int
main(int argc, char **argv)
{
  int argerr = 0 ;
  int arg ;
  char ch ;
  char *f1 ;
  char *f2 ;
  char delim = ',';
  int f[256] ;
  int fi = 0 ;

  f[0] = 1 ;
  fi = 1 ;
  while ((ch = getopt(argc,argv,"md:f:n")) != -1) {
    switch (ch) {
      case 'm':
        show_prefix = 1 ;
        break ;
      case 'd':
        delim = *optarg ;
        break ;
      case 'f':
        f1 = optarg ;
        fi = 0 ;
        do {
          f[fi++] = atoi(f1) ;
          if ((f2 = strchr(f1,','))) f1 = ++f2 ; 
          else f1 = 0 ;
          }
        while (f1 && *f1) ;
        break ;
      case 'n':
        use_names = 1 ;
        break ;
      case '?':
      default:
        usage() ;
      }
    }
  argc -= optind ;
  argv += optind  ;
  if (!argc) {
    if (!read_dump("bgp4.txt")) {
      fprintf(stderr,"ERROR: Cannot open stats file: %s\n","bgp4.txt") ;
      exit(EXIT_FAILURE) ;
      } 
    if (!read_dump("bgp6.txt")) {
      fprintf(stderr,"ERROR: Cannot open stats file: %s\n","bgp6.txt") ;
      exit(EXIT_FAILURE) ;
      }
    }
  else {
    for (arg = 0; arg < argc; arg++) {
      //    printf("%d = %s\n", arg,argv[arg]) ;
      if (!read_dump(argv[arg])) {
        fprintf(stderr,"ERROR: Cannot open BGP dump: %s\n",argv[arg]) ;
        exit(EXIT_FAILURE) ;
        } 
      }
    }


  v4head = 0 ;
  aggregate4 = 0 ;
  avldepthfirst(addresses4,link4,0,0) ;
  deaggregate4() ;

  v6head = 0 ;
  aggregate6 = 0 ;
  avldepthfirst(addresses6,link6,0,0) ;
  deaggregate6() ;

  // avldepthfirst(addresses6,print_addr6,0,0) ;
  // exit(1) ;

  if (use_names) {
    if (!read_as_names("asn.txt")) {
      fprintf(stderr,"ERROR: Cannot open ASN label file: %s\n","asn.txt") ;
      exit(EXIT_FAILURE) ;
      }

    }
  process_prefix_list(delim,f,fi,show_prefix) ;
}
