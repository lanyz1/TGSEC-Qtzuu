#Python3
#Keep the .pem files from lets encrypt
#Logs POST requests
import tornado.httpserver
import tornado.ioloop
import tornado.web

class getToken(tornado.web.RequestHandler):
    def get(self):
        self.write("hello")
        print(self.request.uri)
    def post(self):
        self.write("hello")
        print(self.request.uri)
        print(self.request.body)

application = tornado.web.Application([
    (r'/.*', getToken),
])

if __name__ == '__main__':
    http_server = tornado.httpserver.HTTPServer(application, ssl_options={
        "certfile": "cert.pem",
        "keyfile": "key.pem",
    })
    http_server.listen(443)
    tornado.ioloop.IOLoop.instance().start()
