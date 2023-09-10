using System;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;
using static HttpApiHelp.HttpApi;


namespace HttpApiHelp
{
    public enum HTTP_VERB
    {
        HttpVerbUnparsed,
        HttpVerbUnknown,
        HttpVerbInvalid,
        HttpVerbOPTIONS,
        HttpVerbGET,
        HttpVerbHEAD,
        HttpVerbPOST,
        HttpVerbPUT,
        HttpVerbDELETE,
        HttpVerbTRACE,
        HttpVerbCONNECT,
        HttpVerbTRACK,
        HttpVerbMOVE,
        HttpVerbCOPY,
        HttpVerbPROPFIND,
        HttpVerbPROPPATCH,
        HttpVerbMKCOL,
        HttpVerbLOCK,
        HttpVerbUNLOCK,
        HttpVerbSEARCH,
        HttpVerbMaximum
    }
    public class HTTPRequest
    {
        private HTTP_VERB m_method;
        private string m_url;
        private Dictionary<string, string> m_headers = new Dictionary<string, string>();
        private string m_body;
        private string m_remoteAddress;
        private ushort m_remotePort;

        public HTTPRequest()
        {
            m_method = HTTP_VERB.HttpVerbGET;
        }

        public HTTP_VERB GetMethod()
        {
            return m_method;
        }

        public ushort GetRemotePort()
        {
            return m_remotePort;
        }

        public string GetRemoteAddress()
        {
            return m_remoteAddress;
        }

        public string GetUrl()
        {
            return m_url;
        }

        public string GetBody()
        {
            return m_body;
        }

        public string GetHeader(string name)
        {
            if (m_headers.ContainsKey(name))
            {
                return m_headers[name];
            }
            return "";
        }

        public bool ContainHeader(string name)
        {
            if (m_headers.ContainsKey(name))
            {
                return true;
            }
            return false;
        }

        public void SetMethod(HTTP_VERB method)
        {
            m_method = method;
        }

        public void SetRemotePort(ushort remotePort)
        {
            m_remotePort = remotePort;
        }

        public void SetRemoteAddress(string remoteAddress)
        {
            m_remoteAddress = remoteAddress;
        }

        public void SetUrl(string url)
        {
            m_url = url;
        }

        public void SetBody(string body)
        {
            m_body = body;
        }

        public void SetHeader(string name, string value)
        {
            m_headers[name] = value;
        }

        public Dictionary<string, string> GetHeaders()
        {
            return m_headers;
        }

        public void AppendBody(string body)
        {
            m_body += body;
        }

        public void ReserveBody(int contentLength)
        {
            m_body.Reverse();
        }
    }

    public class HTTPResponse
    {
        private ushort m_statusCode;
        private string m_reason;
        private Dictionary<string, string> m_headers = new Dictionary<string, string>();
        private string m_body;

        public HTTPResponse()
        {
            m_statusCode = 200;
        }

        public void SetStatusCode(ushort statusCode)
        {
            m_statusCode = statusCode;
        }

        public void SetHeader(string key, string value)
        {
            m_headers[key] = value;
        }

        public void SetBody(string body)
        {
            m_body = body;
        }

        public void SetReason(string reason)
        {
            m_reason = reason;
        }

        public void SetContentRange(string conteneRange)
        {
            m_headers["Content-Range"] = conteneRange;
        }

        public void SetContentType(string contentType)
        {
            m_headers["Content-Type"] = contentType;
        }

        public void SetAcceptRanges(string acceptRanges)
        {
            m_headers["Accept-Ranges"] = acceptRanges;
        }

        public void Response500()
        {
            SetStatusCode(500);
            SetReason("500 Server Error");
            SetContentType("text/html;charset=utf-8");
            SetBody("500 Server Error");
        }

        public void Response404()
        {
            SetStatusCode(404);
            SetReason("404 Not Found");
            SetContentType("text/html;charset=utf-8");
            SetBody("404 Not Found");
        }

        public void WriteText(string text)
        {
            SetStatusCode(200);
            SetReason("OK");
            SetContentType("application/json;charset=utf-8");
            SetBody(text);
        }

        public ushort GetStatusCode()
        {
            return m_statusCode;
        }

        public string GetReason()
        {
            return m_reason;
        }

        public string GetHeader(string name)
        {
            if (m_headers.ContainsKey(name))
            {
                return m_headers[name];
            }
            return "";
        }

        public Dictionary<string, string> GetHeaders()
        {
            return m_headers;
        }

        public string GetBody()
        {
            return m_body;
        }
    }

    public delegate void RouteHandlerDelegate(HTTPRequest request, HTTPResponse response);

    public class HTTPServer
    {
        private UInt64 m_sessionID = 0;
        private UInt64 m_groupID = 0;
        private IntPtr m_reqQueue = IntPtr.Zero;
        private string m_webPath = "";
        private Dictionary<string, RouteHandlerDelegate> m_routes = new Dictionary<string, RouteHandlerDelegate>();
        private bool m_start;
        private List<string> m_headerNames = new List<string>(){"Cache-Control", "Connection", "Date", "KeepAlive",
        "Pragma", "Trailer", "Transfer-Encoding", "Upgrade", "Via", "Warning", "Allow", "Content-Length",
        "Content-Type", "Content-Encoding", "Content-Language", "Content-Location", "Content-Md5", "Content-Range",
        "Expires", "Last-Modified", "Accept", "Accept-Charset", "Accept-Encoding", "Accept-Language", "Authorization",
        "Cookie", "Expect", "From", "Host", "If-Match", "If-ModifiedSince", "If-NoneMatch", "If-Range", "If-UnmodifiedSince",
        "Max-Forwards", "Proxy-Authorization", "Referer", "Range", "Te", "Translate", "User-Agent"};

        public bool Init(string serverName, ushort port, string webPath = "")
        {
            HttpApi.HTTPAPI_VERSION version = new HttpApi.HTTPAPI_VERSION();
            version.HttpApiMajorVersion = 2;
            version.HttpApiMinorVersion = 0;
            if (HttpInitialize(version, 3, default) == 0)
            {
                if (HttpApi.HttpCreateServerSession(version, out m_sessionID) == 0)
                {
                    if (HttpApi.HttpCreateUrlGroup(m_sessionID, out m_groupID) == 0)
                    {
                        if (HttpApi.HttpCreateRequestQueue(version, serverName, IntPtr.Zero, 0, out m_reqQueue) == 0)
                        {
                            HTTP_BINDING_INFO BindingProperty = new HTTP_BINDING_INFO();
                            BindingProperty.Flags.Present = 1;
                            BindingProperty.RequestQueueHandle = m_reqQueue;
                            int bindingPropertySize = Marshal.SizeOf(typeof(HTTP_BINDING_INFO));
                            IntPtr bindingPropertyPtr = Marshal.AllocHGlobal(bindingPropertySize);
                            Marshal.StructureToPtr<HTTP_BINDING_INFO>(BindingProperty, bindingPropertyPtr, false);
                            if (HttpSetUrlGroupProperty(m_groupID, HTTP_SERVER_PROPERTY.HttpServerBindingProperty, bindingPropertyPtr, (uint)bindingPropertySize) == 0)
                            {
                                HTTP_TIMEOUT_LIMIT_INFO TimeoutsProperty = new HTTP_TIMEOUT_LIMIT_INFO();
                                TimeoutsProperty.EntityBody = 50;
                                TimeoutsProperty.Flags.Present = 1;
                                int timeoutsPropertySize = Marshal.SizeOf(typeof(HTTP_TIMEOUT_LIMIT_INFO));
                                IntPtr timeoutsPropertyPtr = Marshal.AllocHGlobal(timeoutsPropertySize);
                                Marshal.StructureToPtr<HTTP_TIMEOUT_LIMIT_INFO>(TimeoutsProperty, timeoutsPropertyPtr, false);
                                if (HttpSetUrlGroupProperty(m_groupID, HTTP_SERVER_PROPERTY.HttpServerTimeoutsProperty, timeoutsPropertyPtr, (uint)timeoutsPropertySize) == 0)
                                {
                                    var url = "http://+:" + port.ToString() + "/";
                                    if (HttpAddUrlToUrlGroup(m_groupID, url) == 0)
                                    {
                                        if (webPath == "")
                                        {
                                            webPath = System.AppDomain.CurrentDomain.SetupInformation.ApplicationBase;
                                        }
                                        m_webPath = webPath;
                                        return true;
                                    }
                                    else
                                    {
                                        HttpCloseRequestQueue(m_reqQueue);
                                        HttpApi.HttpCloseUrlGroup(m_groupID);
                                        HttpApi.HttpCloseServerSession(m_sessionID);
                                        HttpApi.HttpTerminate(3, IntPtr.Zero);
                                    }
                                }
                                else
                                {
                                    HttpCloseRequestQueue(m_reqQueue);
                                    HttpApi.HttpCloseUrlGroup(m_groupID);
                                    HttpApi.HttpCloseServerSession(m_sessionID);
                                    HttpApi.HttpTerminate(3, IntPtr.Zero);
                                }
                                Marshal.FreeHGlobal(timeoutsPropertyPtr);
                            }
                            else
                            {
                                HttpCloseRequestQueue(m_reqQueue);
                                HttpApi.HttpCloseUrlGroup(m_groupID);
                                HttpApi.HttpCloseServerSession(m_sessionID);
                                HttpApi.HttpTerminate(3, IntPtr.Zero);
                            }
                            Marshal.FreeHGlobal(bindingPropertyPtr);
                        }
                        else
                        {
                            HttpApi.HttpCloseUrlGroup(m_groupID);
                            HttpApi.HttpCloseServerSession(m_sessionID);
                            HttpApi.HttpTerminate(3, IntPtr.Zero);
                        }
                    }
                    else
                    {
                        HttpApi.HttpCloseServerSession(m_sessionID);
                        HttpApi.HttpTerminate(3, IntPtr.Zero);
                    }
                }
                else
                {
                    HttpApi.HttpTerminate(3, IntPtr.Zero);
                }
            }
            return false;
        }

        public void Bind(string method, string path, RouteHandlerDelegate handler)
        {
            m_routes[method + " " + path] = handler;
        }

        public void Start(int threadNum = 2)
        {
            m_start = true;
            for (int i = 0; i < threadNum; i++)
            {
                new Thread(DoThread).Start();
            }
        }

        private void DoThread()
        {
            HTTP_RESPONSE_V2 pResponse = new HTTP_RESPONSE_V2();
            int RequestBufferLength = Marshal.SizeOf(typeof(HTTP_REQUEST_V2)) + 4098;
            IntPtr pRequest = Marshal.AllocHGlobal(RequestBufferLength);
            int EntityBufferLength = 40960;
            IntPtr pEntityBuffer = Marshal.AllocHGlobal(EntityBufferLength);
            List<byte> buffs = new List<byte>();
            while (m_start)
            {
                var result = HttpReceiveHttpRequest(m_reqQueue, 0, 0, pRequest, (uint)RequestBufferLength, out var byteRead);
                if (result == 0)
                {
                    HTTPRequest req = new HTTPRequest();
                    HTTPResponse resp = new HTTPResponse();
                    buffs.Clear();
                    HTTP_REQUEST_V2 request = (HTTP_REQUEST_V2)Marshal.PtrToStructure(pRequest, typeof(HTTP_REQUEST_V2));
                    req.SetMethod(request.Verb);
                    req.SetUrl(request.CookedUrl.pAbsPath);
                    for (int i = 0; i < request.Headers.UnknownHeaderCount; i++)
                    {
                        IntPtr ptr = (IntPtr)(request.Headers.pUnknownHeaders + i * Marshal.SizeOf(typeof(HTTP_UNKNOWN_HEADER)));
                        var UnknownHeader = (HTTP_UNKNOWN_HEADER)Marshal.PtrToStructure(ptr, typeof(HTTP_UNKNOWN_HEADER));
                        req.SetHeader(UnknownHeader.pName, UnknownHeader.pRawValue);
                    }
                    for (int i = 0; i < 41; i++)
                    {
                        req.SetHeader(m_headerNames[i], request.Headers.KnownHeaders[i].pRawValue);
                    }
                    if ((request.Flags & HTTP_REQUEST_FLAG.HTTP_REQUEST_FLAG_MORE_ENTITY_BODY_EXISTS) == HTTP_REQUEST_FLAG.HTTP_REQUEST_FLAG_MORE_ENTITY_BODY_EXISTS)
                    {
                        while (true)
                        {
                            result = HttpReceiveRequestEntityBody(m_reqQueue, request.RequestId, 0, pEntityBuffer, (uint)EntityBufferLength, out uint byteEntityBufferRead);
                            if (result == 0)
                            {
                                if (byteEntityBufferRead != 0)
                                {
                                    byte[] byteEntityBuffer = new byte[byteEntityBufferRead];
                                    Marshal.Copy(pEntityBuffer, byteEntityBuffer, 0, (int)byteEntityBufferRead);
                                    buffs.AddRange(byteEntityBuffer);
                                }
                            }
                            else if (result == 38)
                            {
                                if (byteEntityBufferRead != 0)
                                {
                                    byte[] byteEntityBuffer = new byte[byteEntityBufferRead];
                                    Marshal.Copy(pEntityBuffer, byteEntityBuffer, 0, (int)byteEntityBufferRead);
                                    buffs.AddRange(byteEntityBuffer);
                                }
                                break;
                            }
                            else
                            {
                                break;
                            }
                        }
                        req.AppendBody(System.Text.Encoding.Default.GetString(buffs.ToArray()));
                    }
                    var reqPath = VerbToString(request.Verb) + " " + request.CookedUrl.pAbsPath;
                    SafeFileHandle fileHandle = null;
                    long start = 0;
                    long length = 0;
                    bool doSendFile = false;
                    if (m_routes.ContainsKey(reqPath))
                    {
                        m_routes[reqPath].Invoke(req, resp);
                    }
                    else
                    {
                        doSendFile = DoUnSubscribe(req, resp, request.CookedUrl.pAbsPath, ref fileHandle, ref start, ref length);
                    }
                    InitResponseStruct(ref pResponse, resp.GetStatusCode(), resp.GetReason());

                    HTTP_DATA_CHUNK chunk = new HTTP_DATA_CHUNK();
                    if (doSendFile)
                    {
                        HTTP_DATA_CHUNK.FROMFILEHANDLE index = new HTTP_DATA_CHUNK.FROMFILEHANDLE();
                        index.FileHandle.handle = fileHandle.DangerousGetHandle();
                        index.ByteRange.StartingOffset = (ulong)start;
                        index.ByteRange.Length = (ulong)length;
                        chunk.DataChunkType = HTTP_DATA_CHUNK_TYPE.HttpDataChunkFromFileHandle;
                        chunk.FromFileHandle = index;
                    }
                    else
                    {
                        var body = resp.GetBody();
                        HttpApi.HTTP_DATA_CHUNK.FROMMEMORY index = new HttpApi.HTTP_DATA_CHUNK.FROMMEMORY();
                        index.pBuffer = Marshal.StringToHGlobalAnsi(body);
                        index.BufferLength = (uint)GetStrLength(body);
                        chunk.DataChunkType = HTTP_DATA_CHUNK_TYPE.HttpDataChunkFromMemory;
                        chunk.FromMemory = index;

                    }
                    var pChunkHeader = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(HTTP_DATA_CHUNK)));
                    Marshal.StructureToPtr<HTTP_DATA_CHUNK>(chunk, pChunkHeader, false);
                    pResponse.EntityChunkCount = 1;
                    pResponse.pEntityChunks = pChunkHeader;
                    bool skip = false;
                    List<HTTP_UNKNOWN_HEADER> unknownHeader = new List<HTTP_UNKNOWN_HEADER>();
                    var headers = resp.GetHeaders();
                    int j = 0;
                    foreach (var header in headers)
                    {
                        if (header.Key == "Content-Type")
                        {
                            skip = true;
                        }
                        if (m_headerNames.Contains(header.Key))
                        {
                            AddKnownHeader(ref pResponse, j, header.Value);
                            continue;
                        }
                        HTTP_UNKNOWN_HEADER headerToAdd = new HTTP_UNKNOWN_HEADER();
                        headerToAdd.pName = header.Key;
                        headerToAdd.NameLength = (ushort)header.Key.Length;
                        headerToAdd.pRawValue = header.Value;
                        headerToAdd.RawValueLength = (ushort)header.Value.Length;
                        unknownHeader.Add(headerToAdd);
                    }
                    if (!skip)
                    {
                        AddKnownHeader(ref pResponse, 12, "application/json;charset=utf-8");
                    }
                    AddUnKnownHeader(ref pResponse, unknownHeader);
                    var ret = HttpSendHttpResponse(m_reqQueue, request.RequestId, 0, pResponse, IntPtr.Zero, out var byteSent, IntPtr.Zero, 0, IntPtr.Zero, IntPtr.Zero);
                    Marshal.FreeHGlobal(pChunkHeader);
                }
                else if (result == 6)
                {
                    break;
                }
            }
            Marshal.FreeHGlobal(pRequest);
            Marshal.FreeHGlobal(pEntityBuffer);
        }

        public void Stop()
        {
            m_start = false;
            System.Threading.Thread.Sleep(50);
            if (m_groupID != 0)
            {
                HttpRemoveUrlFromUrlGroup(m_groupID, "", 1);
                HttpCloseUrlGroup(m_groupID);
                m_groupID = 0;
            }
            if (m_sessionID != 0)
            {
                HttpCloseServerSession(m_sessionID);
                m_sessionID = 0;
            }
            if (m_reqQueue != IntPtr.Zero)
            {
                HttpCloseRequestQueue(m_reqQueue);
                m_reqQueue = IntPtr.Zero;
                HttpTerminate(1, IntPtr.Zero);
            }
        }

        private string VerbToString(HTTP_VERB verb)
        {
            string ret = "GET";
            switch (verb)
            {
                case HTTP_VERB.HttpVerbGET: ret = "GET"; break;
                case HTTP_VERB.HttpVerbHEAD: ret = "HEAD"; break;
                case HTTP_VERB.HttpVerbPOST: ret = "POST"; break;
                case HTTP_VERB.HttpVerbPUT: ret = "PUT"; break;
                case HTTP_VERB.HttpVerbDELETE: ret = "DELETE"; break;
                case HTTP_VERB.HttpVerbCONNECT: ret = "CONNECT"; break;
                case HTTP_VERB.HttpVerbCOPY: ret = "COPY"; break;
                case HTTP_VERB.HttpVerbOPTIONS: ret = "OPTIONS"; break;
                default: ret = "GET"; break;
            }
            return ret;
        }

        private void InitResponseStruct(ref HTTP_RESPONSE_V2 httpResponse, ushort statusCode, string reason)
        {
            httpResponse.StatusCode = statusCode;
            httpResponse.pReason = reason;
            httpResponse.ReasonLength = (ushort)reason.Length;
            httpResponse.Headers.KnownHeaders = new HTTP_KNOWN_HEADER[41];
        }

        private void AddUnKnownHeader(ref HTTP_RESPONSE_V2 httpResponse, List<HTTP_UNKNOWN_HEADER> unknownHeader)
        {
            var pUnknownHeader = Marshal.AllocHGlobal(unknownHeader.Count * Marshal.SizeOf(typeof(HTTP_UNKNOWN_HEADER)));
            long LongPtr = pUnknownHeader.ToInt64();
            for (int i = 0; i < unknownHeader.Count; i++)
            {
                IntPtr RectPtr = new IntPtr(LongPtr);
                Marshal.StructureToPtr(unknownHeader[i], RectPtr, false);
                LongPtr += Marshal.SizeOf(typeof(HTTP_UNKNOWN_HEADER));
            }
            httpResponse.Headers.pUnknownHeaders = pUnknownHeader;
            httpResponse.Headers.UnknownHeaderCount = (ushort)unknownHeader.Count;
        }

        private void AddKnownHeader(ref HTTP_RESPONSE_V2 httpResponse, int index, string value)
        {
            httpResponse.Headers.KnownHeaders[index].pRawValue = value;
            httpResponse.Headers.KnownHeaders[index].RawValueLength = (ushort)(value.Length);
        }

        private bool DoUnSubscribe(HTTPRequest request, HTTPResponse response, string absPath, ref SafeFileHandle fileHandle, ref long start, ref long length)
        {
            var path = absPath.Replace('/', '\\');
            if (path == "\\")
            {
                path = "index.html";
            }
            path = System.Web.HttpUtility.UrlDecode(path);
            var newPath = m_webPath + path;
            if (!System.IO.File.Exists(newPath))
            {
                response.Response404();
                return false;
            }
            var stream = System.IO.File.Open(newPath, FileMode.Open);
            fileHandle = stream.SafeFileHandle;
            var fileSize = new FileInfo(newPath).Length;
            string status;
            ushort statusCode;
            long startOffset;
            long endOffset;
            if (request.ContainHeader("Range") && request.GetHeader("Range") != "")
            {
                var range = request.GetHeader("Range");
                startOffset = Convert.ToInt64(Between(range, "=", "-"));
                if (range.Substring(range.Length - 1, 1) == "-")
                {
                    endOffset = (fileSize < 16380) ? fileSize : startOffset < fileSize ? (startOffset + 16380) : fileSize;
                }
                else
                {
                    endOffset = Convert.ToInt64(GetRight(range, "-"));
                }
                status = "Partial Content";
                statusCode = 206;
            }
            else
            {
                status = "OK";
                statusCode = 200;
                startOffset = 0;
                endOffset = fileSize;
            }
            string contentRange = "bytes " + startOffset.ToString() + "-" + endOffset.ToString() + "/" + fileSize.ToString();
            response.SetContentRange(contentRange);
            response.SetStatusCode(statusCode);
            response.SetReason(status);
            var ext = Path.GetExtension(path);
            var typeName = ExtToContentType(ext);
            if (typeName != "html" || typeName != "htm")
            {
                response.SetContentType(typeName);
            }
            if (fileSize > 163840)
            {
                response.SetAcceptRanges("bytes");
            }
            start = startOffset;
            length = endOffset - startOffset;
            return true;
        }

        private string Between(string str, string leftStr, string rightStr, bool ignoreCase = false)
        {
            StringComparison comparison = StringComparison.CurrentCulture;
            if (ignoreCase)
            {
                comparison = StringComparison.OrdinalIgnoreCase;
            }
            int index = str.IndexOf(leftStr, comparison);
            if (index == -1) return "";
            int i = index + leftStr.Length;
            int last = str.IndexOf(rightStr, i, comparison);
            if (last == -1) return "";
            return str.Substring(i, last - i);
        }

        private int GetStrLength(string str)
        {
            if (string.IsNullOrEmpty(str)) return 0;
            ASCIIEncoding ascii = new ASCIIEncoding();
            int tempLen = 0;
            byte[] s = ascii.GetBytes(str);
            for (int i = 0; i < s.Length; i++)
            {
                if ((int)s[i] == 63)
                {
                    tempLen += 2;
                }
                else
                {
                    tempLen += 1;
                }
            }
            return tempLen;
        }

        private string GetRight(string str, string right, bool ignoreCase = false)
        {
            StringComparison comparison = StringComparison.CurrentCulture;
            if (ignoreCase)
            {
                comparison = StringComparison.OrdinalIgnoreCase;
            }
            int index = str.LastIndexOf(right, comparison);
            if (index == -1) return "";
            int index_start = index + right.Length;
            int end_len = str.Length - index_start;
            string temp = str.Substring(index_start, end_len);
            return temp;
        }

        private static string ExtToContentType(string ext)
        {
            ext = ext.ToLower();
            if (ext == "*")
            {
                return "application/octet-stream";
            }
            else if (ext == "pdf")
            {
                return "application/pdf";
            }
            else if (ext == "js")
            {
                return "application/x-javascript";
            }
            else if (ext == "json")
            {
                return "application/json";
            }
            else if (ext == "xml")
            {
                return "application/xml";
            }
            else if (ext == "xhtml")
            {
                return "application/xhtml";
            }
            else if (ext == "zip")
            {
                return "application/zip";
            }
            else if (ext == "gzip")
            {
                return "application/gzip";
            }
            else if (ext == "xls")
            {
                return "application/x-xls";
            }
            else if (ext == "bmp")
            {
                return "application/x-bmp";
            }
            else if (ext == "cer")
            {
                return "application/x-x509-ca-cert";
            }
            else if (ext == "crt")
            {
                return "application/x-x509-ca-cert";
            }
            else if (ext == "so")
            {
                return "application/octet-stream";
            }
            else if (ext == "dll")
            {
                return "application/x-msdownload";
            }
            else if (ext == "dot")
            {
                return "application/msword";
            }
            else if (ext == "der")
            {
                return "application/x-x509-ca-cert";
            }
            else if (ext == "doc")
            {
                return "application/msword";
            }
            else if (ext == "exe")
            {
                return "application/x-msdownload";
            }
            else if (ext == "p12")
            {
                return "application/x-pkcs12";
            }
            else if (ext == "pfx")
            {
                return "application/x-pkcs12";
            }
            else if (ext == "ppt")
            {
                return "application/x-ppt";
            }
            else if (ext == "css")
            {
                return "text/csv";
            }
            else if (ext == "html")
            {
                return "text/html;charset=utf-8";
            }
            else if (ext == "htm")
            {
                return "text/html;charset=utf-8";
            }
            else if (ext == "txt")
            {
                return "text/plain";
            }
            else if (ext == "mp4")
            {
                return "video/mpeg4";
            }
            else if (ext == "jpeg")
            {
                return "image/jpeg";
            }
            else if (ext == "jpg")
            {
                return "image/jpeg";
            }
            else if (ext == "png")
            {
                return "image/png";
            }
            else if (ext == "png")
            {
                return "image/png";
            }
            else
            {
                return "application/octet-stream";
            }
        }
    }


    public static class HttpApi
    {
        public enum HTTP_DATA_CHUNK_TYPE
        {
            HttpDataChunkFromMemory,
            HttpDataChunkFromFileHandle,
            HttpDataChunkFromFragmentCache,
            HttpDataChunkFromFragmentCacheEx,
            HttpDataChunkTrailers,
            HttpDataChunkMaximum,
        }
        public enum HTTP_SERVER_PROPERTY
        {
            HttpServerAuthenticationProperty,
            HttpServerLoggingProperty,
            HttpServerQosProperty,
            HttpServerTimeoutsProperty,
            HttpServerQueueLengthProperty,
            HttpServerStateProperty,
            HttpServer503VerbosityProperty,
            HttpServerBindingProperty,
            HttpServerExtendedAuthenticationProperty,
            HttpServerListenEndpointProperty,
            HttpServerChannelBindProperty,
            HttpServerProtectionLevelProperty,
            HttpServerDelegationProperty = 16,
        }

        public enum HTTP_REQUEST_FLAG
        {
            HTTP_REQUEST_FLAG_MORE_ENTITY_BODY_EXISTS = 0x00000001,
            HTTP_REQUEST_FLAG_IP_ROUTED = 0x00000002,
            HTTP_REQUEST_FLAG_HTTP2 = 0x00000004,
            HTTP_REQUEST_FLAG_HTTP3 = 0x00000008,
        }

        public struct HTTPAPI_VERSION
        {
            public ushort HttpApiMajorVersion;
            public ushort HttpApiMinorVersion;
        }

        public struct HTTP_PROPERTY_FLAGS
        {
            public uint Present;
        }

        public struct HTTP_BINDING_INFO
        {
            public HTTP_PROPERTY_FLAGS Flags;
            public IntPtr RequestQueueHandle;
        }

        public struct HTTP_TIMEOUT_LIMIT_INFO
        {
            public HTTP_PROPERTY_FLAGS Flags;
            public ushort EntityBody;
            public ushort DrainEntityBody;
            public ushort RequestQueue;
            public ushort IdleConnection;
            public ushort HeaderWait;
            public uint MinSendRate;
        }

        public struct HTTP_VERSION
        {
            public ushort MajorVersion;
            public ushort MinorVersion;
        }

        public struct HTTP_COOKED_URL
        {
            public ushort FullUrlLength;
            public ushort HostLength;
            public ushort AbsPathLength;
            public ushort QueryStringLength;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string pFullUrl;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string pHost;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string pAbsPath;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string pQueryString;
        }

        public struct HTTP_TRANSPORT_ADDRESS
        {
            private IntPtr pRemoteAddress;
            private IntPtr pLocalAddress;
        }

        public struct HTTP_KNOWN_HEADER
        {
            public ushort RawValueLength;
            [MarshalAs(UnmanagedType.LPStr)]
            public string pRawValue;
        }

        public struct HTTP_UNKNOWN_HEADER
        {
            public ushort NameLength;
            public ushort RawValueLength;
            [MarshalAs(UnmanagedType.LPStr)]
            public string pName;
            [MarshalAs(UnmanagedType.LPStr)]
            public string pRawValue;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct HTTP_REQUEST_HEADERS
        {
            public ushort UnknownHeaderCount;
            public IntPtr pUnknownHeaders;
            public ushort TrailerCount;
            public IntPtr pTrailers;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 41)]
            public HTTP_KNOWN_HEADER[] KnownHeaders;
        }

        public struct HTTP_REQUEST_V2
        {
            public HTTP_REQUEST_FLAG Flags;
            public UInt64 ConnectionId;
            public UInt64 RequestId;
            public UInt64 UrlContext;
            public HTTP_VERSION Version;
            public HTTP_VERB Verb;
            public ushort UnknownVerbLength;
            public ushort RawUrlLength;
            [MarshalAs(UnmanagedType.LPStr)]
            public string pUnknownVerb;
            [MarshalAs(UnmanagedType.LPStr)]
            public string pRawUrl;
            public HTTP_COOKED_URL CookedUrl;
            public HTTP_TRANSPORT_ADDRESS Address;
            public HTTP_REQUEST_HEADERS Headers;
            public ulong BytesReceived;
            public ushort EntityChunkCount;
            public IntPtr pEntityChunks;
            public UInt64 RawConnectionId;
            public IntPtr pSslInfo;
            public ushort RequestInfoCount;
            public IntPtr pRequestInfo;
        }

        public struct HTTP_RESPONSE_HEADERS
        {
            public ushort UnknownHeaderCount;
            public IntPtr pUnknownHeaders;
            public ushort TrailerCount;
            public IntPtr pTrailers;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 30)]
            public HTTP_KNOWN_HEADER[] KnownHeaders;
        }

        public struct HTTP_RESPONSE_V2
        {
            public uint Flags;
            public HTTP_VERSION Version;
            public ushort StatusCode;
            public ushort ReasonLength;
            [MarshalAs(UnmanagedType.LPStr)]
            public string pReason;
            public HTTP_RESPONSE_HEADERS Headers;
            public ushort EntityChunkCount;
            public IntPtr pEntityChunks;
            public ushort ResponseInfoCount;
            public IntPtr pResponseInfo;
        }

        public struct HTTP_BYTE_RANGE
        {
            public ulong StartingOffset;
            public ulong Length;
        }

        public struct HFILE
        {
            public IntPtr handle;
        }

        public struct HTTP_DATA_CHUNK
        {
            [StructLayout(LayoutKind.Explicit)]
            private struct UNION
            {
                [FieldOffset(0)]
                public FROMMEMORY FromMemory;

                [FieldOffset(0)]
                public FROMFILEHANDLE FromFileHandle;

                [FieldOffset(0)]
                public FROMFRAGMENTCACHE FromFragmentCache;

                [FieldOffset(0)]
                public FROMFRAGMENTCACHEEX FromFragmentCacheEx;

                [FieldOffset(0)]
                public TRAILERS Trailers;
            }

            public struct FROMMEMORY
            {
                public IntPtr pBuffer;
                public uint BufferLength;
            }

            public struct FROMFILEHANDLE
            {
                public HTTP_BYTE_RANGE ByteRange;
                public HFILE FileHandle;
            }

            public struct FROMFRAGMENTCACHE
            {
                public ushort FragmentNameLength;
                public IntPtr pFragmentName;
            }

            public struct FROMFRAGMENTCACHEEX
            {
                public HTTP_BYTE_RANGE ByteRange;
                public IntPtr pFragmentName;
            }

            public struct TRAILERS
            {
                public ushort TrailerCount;
                public IntPtr pTrailers;
            }

            public HTTP_DATA_CHUNK_TYPE DataChunkType;

            private UNION union;

            public FROMMEMORY FromMemory
            {
                get
                {
                    return union.FromMemory;
                }
                set
                {
                    union.FromMemory = value;
                }
            }

            public FROMFILEHANDLE FromFileHandle
            {
                get
                {
                    return union.FromFileHandle;
                }
                set
                {
                    union.FromFileHandle = value;
                }
            }

            public FROMFRAGMENTCACHE FromFragmentCache
            {
                get
                {
                    return union.FromFragmentCache;
                }
                set
                {
                    union.FromFragmentCache = value;
                }
            }

            public FROMFRAGMENTCACHEEX FromFragmentCacheEx
            {
                get
                {
                    return union.FromFragmentCacheEx;
                }
                set
                {
                    union.FromFragmentCacheEx = value;
                }
            }

            public TRAILERS Trailers
            {
                get
                {
                    return union.Trailers;
                }
                set
                {
                    union.Trailers = value;
                }
            }
        }

        [DllImport("httpapi.dll", SetLastError = true)]
        public static extern uint HttpInitialize(HTTPAPI_VERSION Version, uint Flags, IntPtr pReserved);

        [DllImport("httpapi.dll", SetLastError = true)]
        public static extern uint HttpCreateServerSession(HTTPAPI_VERSION Version, out UInt64 ServerSessionId, uint Reserved = 0);

        [DllImport("httpapi.dll", SetLastError = true)]
        public static extern uint HttpTerminate(uint Flags, IntPtr pReserved);

        [DllImport("httpapi.dll", SetLastError = true)]
        public static extern uint HttpCreateUrlGroup(UInt64 ServerSessionId, out UInt64 pUrlGroupId, uint Reserved = 0);

        [DllImport("httpapi.dll", SetLastError = true)]
        public static extern uint HttpCloseServerSession(UInt64 ServerSessionId);

        [DllImport("httpapi.dll", SetLastError = true)]
        public static extern uint HttpCreateRequestQueue(HTTPAPI_VERSION Version, [Optional, MarshalAs(UnmanagedType.LPWStr)] string name, [In, Optional] IntPtr SecurityAttributes, [In, Optional] uint Flags, out IntPtr RequestQueueHandle);

        [DllImport("httpapi.dll", SetLastError = true)]
        public static extern uint HttpCloseUrlGroup(UInt64 pUrlGroupId);

        [DllImport("httpapi.dll", SetLastError = true)]
        public static extern uint HttpSetUrlGroupProperty(UInt64 pUrlGroupId, HTTP_SERVER_PROPERTY Property, [In] IntPtr PropertyInformation, [In] uint PropertyInformationLength);

        [DllImport("httpapi.dll", SetLastError = true)]
        public static extern uint HttpCloseRequestQueue(IntPtr RequestQueueHandle);

        [DllImport("httpapi.dll", SetLastError = true)]
        public static extern uint HttpAddUrlToUrlGroup(UInt64 pUrlGroupId, [MarshalAs(UnmanagedType.LPWStr)] string pFullyQualifiedUrl,
        [In, Optional] ulong UrlContext, uint Reserved = 0);

        [DllImport("httpapi.dll", SetLastError = true)]
        public static extern uint HttpReceiveHttpRequest([In] IntPtr RequestQueueHandle, [In] UInt64 RequestId,
        [In] uint Flags, [Out] IntPtr RequestBuffer, [In] uint RequestBufferLength, out uint BytesReturned, [In, Optional] IntPtr Overlapped);

        [DllImport("httpapi.dll", SetLastError = true)]
        public static extern uint HttpReceiveRequestEntityBody([In] IntPtr RequestQueueHandle, [In] UInt64 RequestId,
        [In] uint Flags, [Out] IntPtr EntityBuffer, [In] uint EntityBufferLength, out uint BytesReturned,
        [In, Optional] IntPtr Overlapped);

        [DllImport("httpapi.dll", SetLastError = true)]
        public static extern uint HttpSendHttpResponse([In] IntPtr RequestQueueHandle, [In] UInt64 RequestId, [In] uint Flags,
        in HTTP_RESPONSE_V2 HttpResponse, [In, Optional] IntPtr CachePolicy, out uint BytesSent, [In, Optional] IntPtr Reserved1, [In, Optional] uint Reserved2,
        [In, Optional] IntPtr Overlapped, [In, Optional] IntPtr LogData);

        [DllImport("httpapi.dll", SetLastError = true)]
        public static extern uint HttpRemoveUrlFromUrlGroup([In] UInt64 UrlGroupId, [MarshalAs(UnmanagedType.LPWStr)] string pFullyQualifiedUrl,
        [In, Optional] uint Flags);
    }
}
