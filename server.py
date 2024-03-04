import websockets.sync.server as web
import websockets.exceptions
import json, os, time, random, logging, threading, bcrypt, base64, datetime, importlib, ssl, pathlib, urllib.request, progressbar
from cryptography.fernet import Fernet

pbar = None

def _show_progress(block_num, block_size, total_size):
    global pbar
    if pbar is None:
        widgets = ["Downloading SSL certificate: ",progressbar.Bar(),"",progressbar.Percentage()," ",progressbar.ETA()]
        pbar = progressbar.ProgressBar(maxval=total_size,widgets=widgets,line_breaks = False)
        pbar.start()

    downloaded = block_num * block_size
    if downloaded < total_size:
        pbar.update(downloaded)
    else:
        pbar.finish()
        pbar = None

#Installs directory

if os.path.exists("localhost.pem"):
    urllib.request.urlretrieve("https://websockets.readthedocs.io/en/stable/_downloads/c350abd2963d053f49c19e58cceced69/localhost.pem","localhost.pem",_show_progress)
    


def getfilename():
    name = datetime.datetime.now()
    return f"logs/{name.hour}:{name.minute}:{name.second}_{name.month}-{name.day}-{name.year}.log"

serverlogg = logging.getLogger("Server")
logname = getfilename()
open(logname,mode="w")

logging.basicConfig(filename=logname,filemode="r+",format='[%(name)s][%(asctime)s][%(levelname)s]: %(message)s',datefmt='%I:%M:%S %p',level=logging.INFO)
mainsettings = json.load(open("config/server-config.json"))
version = "v0.1"

def handler(websocket: web.ServerConnection):
    fkey = Fernet.generate_key()
    Fernetencrypt = Fernet(fkey)
    ip = websocket.local_address
    id = websocket.id
    websocket.logger.info(f"A Client with the IP {ip} has connected")
    websocket.logger.info(f"{ip} has now been registered with id: {id}")
    
    #HANDSHAKE STARTS HERE
    webshakehandle = {"serverversion":version,"needauth":mainsettings['needauth'],"ecrypt":fkey.decode()}
    websocket.send(json.dumps(webshakehandle))
    websocket.send(fkey)
    returndata = json.loads(websocket.recv())
    if returndata["msg"] == "ok":
        websocket.logger.info(f"{ip} has connected with correct response")
    
    #Sign in
    if os.listdir("users") == []:
        websocket.logger.warning("Warning")
        websocket.send(json.dumps({"authmsg":"nousers-createone"}))
        username = json.loads(websocket.recv())
        userlogin = {}
        f = open(f"users/{username}","w+")
        
        
    else:
        websocket.send(json.dumps({"authmsg":"awaiting-username"}))
        if mainsettings['needauth']:
            authinfo = {"username":None,"authed":False,"premissons":None}
            while True:
                
                #Recv username and decrypts it
                returndata = websocket.recv()
                de = Fernetencrypt.decrypt(returndata).decode()
                if os.path.exists("users/{}".format(de)):
                    authinfo['username'] = de
                    websocket.send(json.dumps({"authmsg":authinfo['username']}))
                    userfile = json.loads(open("{}.json".format(de),"r"))
                    
                    #Recv password and decrpyts it
                    for i in range(5):
                        returndata = websocket.recv()
                        de = Fernetencrypt.decrypt(returndata).decode()
                        if bcrypt.checkpw(de,userfile['password']):
                            authinfo['authed'] = True
                            authinfo['premissions'] = userfile['premissons']
                            websocket.send(json.dumps({"authmsg":"authsuccess","authinfo":authinfo}))
                            break
                        else:
                            websocket.send(json.dumps({"authmsg":"passwordincorrect"}))
                    
                    if authinfo['authed']:
                        break #Breaks signin loop
                    else:
                        pass
                
                
                else:
                    websocket.send(json.dumps({"authmsg":"notfound"}))
    
    #HANDSHAKE ENDS HERE
    websocket.send("handshakecomplete")
    print(f"CLIENT-{websocket.id} handshake complete")
    while True:
        pass
        

def main():
    logging.info(f"Opening server at \"{mainsettings['host']}\" with the port {mainsettings['port']}")
    
    logging.info("Loading SSL certificate")
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    localhost_pem = pathlib.Path(__file__).with_name("localhost.pem")
    ssl_context.load_cert_chain(localhost_pem)
    
    server = web.serve(handler, mainsettings['host'], mainsettings['port'], ssl_context=ssl_context, logger=serverlogg)
    logging.info("Server is open")
    server.serve_forever()

if __name__ == "__main__":
    logging.info("Server startup initialized")
    main()
else:
    raise ImportError("WCMS \033[1mCANNOT\033[0m be imported")