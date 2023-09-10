# HttpApiServer.Net
web server based on httpapi.dll,stably and efficiently.
#
# Depend on the environment

win10

# example
static void test_http()
        {
            HTTPServer server = new HTTPServer();
            if (server.Init("MyServer", 9000))
            {
                Console.WriteLine("Init ok");

                server.Bind("GET", "/a", OnProc);
                server.Start(1);

            }
            Console.ReadLine();
            server.Stop();
        }

static public void OnProc(HTTPRequest req, HTTPResponse resp)
{
    Console.WriteLine("request path:" + req.GetUrl());
    //Console.WriteLine("remote address:" + req.GetRemoteAddress());
    //Console.WriteLine("remote port:" + req.GetRemotePort());
    var str = req.GetBody();

    Console.WriteLine("postdata:" + str);
    resp.SetHeader("Auth", "william");
    resp.WriteText("我！ok");
}
