import sqlite3

from scapy.all import sendp, send, get_if_list, get_if_hwaddr

class processor():
    
    def pkt_process(self, parse_rs):
        src = get_if_hwaddr("eth0")
        host_id = "host"+str(int(src[15]+src[16], 16))
        #self.conn = sqlite3.connect("/home/poi/Desktop/P4_INT/int_test/DB/%s" % host_id)
        self.conn = sqlite3.connect("/home/poi/Desktop/P4_INT/int_test/DB/test")
        self.c = self.conn.cursor()
        #self.c.execute("DELETE FROM INT_INFO")
        #self.conn.commit()
        if (parse_rs[0]==1):
            ethernet=parse_rs[1]
            ip=parse_rs[2]
            inthdr_list=parse_rs[3]
            print(ip, inthdr_list)
            print(ethernet[1])
            # dstAddr map to the host which holds the table
            sql_fmt1 = "INSERT INTO INT_INFO VALUES "
            sql_fmt2 = "("
            sql_fmt3 = ("null,\"%s\",\"%s\",\"%s\"" % (ip[11], ip[10],ethernet[1]))
            sql_fmt4 = ""
            for i in inthdr_list:
                for j in i:
                    sql_fmt4 = sql_fmt4+(",%d" % j)
            sql_fmt_5 = ")"
            sql_fmt = sql_fmt1+sql_fmt2+sql_fmt3+sql_fmt4+sql_fmt_5
            self.c.execute(sql_fmt)
            self.conn.commit()
            self.conn.close()

