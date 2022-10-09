using static Vanara.PInvoke.HttpApi;
using System.Text;

namespace HttpApiTool
{
    public static class TestHttpApiServer
    {
        static private HttpApiServer m_server = new HttpApiServer();
        public static void testHttpApi()
        {
            if (m_server.Init("MyServer"))
            {
                Console.WriteLine("Init ok");
                if (m_server.BindHttpPort(8989))
                {
                    Console.WriteLine("BindHttpPort ok");
                    m_server.Subscribe("/", OnProc);
                    m_server.Start(1);
                }
            }
        }

        static public void OnProc(SafeHREQQUEUE ReqQueue, HTTP_REQUEST_V2 request, byte[] data)
        {
            HttpApiRequest req = new HttpApiRequest();
            HttpApiResponse resp = new HttpApiResponse();
            req.Init(request, data, true, true);
            resp.Init(ReqQueue, request);
            Console.WriteLine("request path:" + req.GetRequestPath());
            Console.WriteLine("remote address:" + req.GetRemoteAddress());
            var postdata = req.GetPostData();
            Console.WriteLine("postdata len:" + postdata.Length.ToString());
            var str = Encoding.Default.GetString(postdata);
            Console.WriteLine("postdata:" + str);
            resp.SetCustomResponseHeader("Auth", "william");
            resp.SetStatusCode(200, "OK");
            resp.SetContentType("text/html; charset=gb2312");
            resp.WriteText("OK");
        }
    }
}
