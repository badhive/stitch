#parse("C File Header.h")
#set($nameUpper = $NAME)
#set($nameUpper = $nameUpper.toUpperCase())
#set($dirUpper = $DIR_PATH)
#set($dirUpper = $dirUpper.replace("\\", "/"))
#set($s1 = $dirUpper.indexOf("/"))
#set($dirUpper = $dirUpper.substring($s1 + 1))
#set($dirUpper = $dirUpper.replace("/", "_").toUpperCase())
#[[#ifndef]]# ${dirUpper}_${nameUpper}_H_
#[[#define]]# ${dirUpper}_${nameUpper}_H_

#[[#endif]]# //${dirUpper}_${nameUpper}_H_