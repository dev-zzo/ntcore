#ifndef __NTAPIVER_H_INCLUDED
#define __NTAPIVER_H_INCLUDED

#define NTAPI_MAKE_LEVEL(maj, min, sp, bld) (((maj << 28) | (min << 24) | (sp << 16) | (bld)))

/* Versions:
   Windows 2000
*/
#define NTAPI_LEVEL_WIN2K NTAPI_MAKE_LEVEL(5,0,0,0)

/* Versions:
   Windows XP
*/
#define NTAPI_LEVEL_WINXP NTAPI_MAKE_LEVEL(5,1,0,0)

/* Versions:
   Windows XP Professional x64 Edition
   Windows Home Server
   Windows Server 2003
   Windows Server 2003 R2
*/
#define NTAPI_LEVEL_WINXP64 NTAPI_MAKE_LEVEL(5,2,0,0)

/* Versions:
   Windows Vista
   Windows Server 2008
*/
#define NTAPI_LEVEL_VISTA NTAPI_MAKE_LEVEL(6,0,0,0)

/* Versions:
   Windows 7
   Windows Server 2008 R2
*/
#define NTAPI_LEVEL_WIN7 NTAPI_MAKE_LEVEL(6,1,0,0)
#define NTAPI_LEVEL_WIN7_SP1 NTAPI_MAKE_LEVEL(6,1,1,0)

/* Versions:
   Windows 8
   Windows Server 2012
*/
#define NTAPI_LEVEL_WIN8 NTAPI_MAKE_LEVEL(6,2,0,0)

/* Versions:
   Windows 8.1
   Windows Server 2012 R2
*/
#define NTAPI_LEVEL_WIN8_1 NTAPI_MAKE_LEVEL(6,3,0,0)

/* Versions:
   Windows 10
   Windows Server 2016
*/
#define NTAPI_LEVEL_WIN10 NTAPI_MAKE_LEVEL(10,0,0,0)

#endif
