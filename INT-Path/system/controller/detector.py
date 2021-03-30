import redis
import time

r = redis.Redis(unix_socket_path='/var/run/redis/redis.sock')
pubsub=r.pubsub()
pubsub.psubscribe('__keyevent@0__:expired')

error=None
while(True):
    message=pubsub.get_message() 
    if(message!=None):
        data=message['data']
        #if(data!=1):
            #port_list=data.decode().split("+")[4:]
            ## print(port_list)
            ##if error==None:
            ##    error=port_list
            ##else:
            ##    error=list(set(error).intersection(set(port_list)))
            #error = port_list
        print("DATA {} TIME {}".format(data, time.time()), flush=True)
        #print("ERROR {} TIME {}".format(error, time.time()), flush=True)
                
                    


