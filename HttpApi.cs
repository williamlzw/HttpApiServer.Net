using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;
using Vanara.PInvoke;
using static Vanara.PInvoke.HttpApi;
using static Vanara.PInvoke.Ws2_32;
using static Vanara.PInvoke.HttpApi.HTTP_DATA_CHUNK;


namespace HttpApiTool
{
    public delegate void SubscribeProcDelegate(SafeHREQQUEUE hReqQueue, HTTP_REQUEST_V2 request, byte[] data);

    public class HttpApiServer
    {
        private SafeHTTP_SERVER_SESSION_ID m_sessionID = null;
        private SafeHTTP_URL_GROUP_ID m_groupID = null;
        private SafeHREQQUEUE m_reqQueue = null;
        private string m_defaultFile = "";
        private string m_webPath = "";
        private string m_htmlFilePath = "";
        private List<string> m_banFile = new List<string>();
        private Dictionary<string, SubscribeProcDelegate> m_SubscribeMap = new Dictionary<string, SubscribeProcDelegate>();
        private bool m_start = false;
        private List<Thread> m_thread = new List<Thread>();

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

        private static string ExtToContentType(string ext)
        {
            ext = ext.ToLower();
            if(ext == "*")
            {
                return "application/octet-stream";
            }
            else if(ext == "pdf")
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
        private void OnThreadRequestCallback()
        {
            int RequestBufferLength = Marshal.SizeOf(typeof(HTTP_REQUEST_V2)) + 4098;
            IntPtr pRequest = Marshal.AllocHGlobal(RequestBufferLength);
            int EntityBufferLength = 40960;
            IntPtr pEntityBuffer = Marshal.AllocHGlobal(EntityBufferLength);
            List<byte> buffs = new List<byte>();
            do
            {
                uint byteRead = 0;
                var result = HttpReceiveHttpRequest(m_reqQueue, 0, 0, pRequest, (uint)RequestBufferLength, out byteRead);

                if (result == Win32Error.NO_ERROR)
                {
                    HTTP_REQUEST_V2 request = (HTTP_REQUEST_V2)Marshal.PtrToStructure(pRequest, typeof(HTTP_REQUEST_V2));
                    var verb = request.Verb;
                    var absPath = request.CookedUrl.pAbsPath;
                    if(verb == HTTP_VERB.HttpVerbGET)
                    {
                        
                        if (m_SubscribeMap.ContainsKey(absPath))
                        {
                           var call =  m_SubscribeMap[absPath];
                           call(m_reqQueue, request, new byte[0]);
                        }
                        else
                        {
                            DoUnSubscribe(m_reqQueue, request, new byte[0], absPath);
                        }
                    }
                    else if(verb == HTTP_VERB.HttpVerbPOST)
                    {
                        var flags = request.Flags;
                        if((flags & HTTP_REQUEST_FLAG.HTTP_REQUEST_FLAG_MORE_ENTITY_BODY_EXISTS) != 0)
                        {
                            do
                            {
                                result = HttpReceiveRequestEntityBody(m_reqQueue, request.RequestId, 0, pEntityBuffer, (uint)EntityBufferLength, out uint byteEntityBufferRead);
                                if (result == Win32Error.NO_ERROR)
                                {
                                    if(byteEntityBufferRead != 0)
                                    {
                                        byte[] byteEntityBuffer = new byte[byteEntityBufferRead];
                                        Marshal.Copy(pEntityBuffer, byteEntityBuffer, 0, (int)byteEntityBufferRead);
                                        buffs.AddRange(byteEntityBuffer);
                                    }
                                }
                                else if(result == Win32Error.ERROR_HANDLE_EOF)
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
                            } while (true);
                            var totalBuff = buffs.ToArray();
                            if(m_SubscribeMap.ContainsKey(absPath))
                            {
                                var call = m_SubscribeMap[absPath];
                                call(m_reqQueue, request, totalBuff);
                            }
                            else
                            {
                                DoUnSubscribe(m_reqQueue, request, totalBuff, absPath);
                            }
                        }
                    }
                }
                else if(result == Win32Error.ERROR_INVALID_HANDLE)
                {
                    break;
                }
            } while (m_start);
            Marshal.FreeHGlobal(pEntityBuffer);
            Marshal.FreeHGlobal(pRequest);
        }

        private void DoUnSubscribe(SafeHREQQUEUE reqQueue, HTTP_REQUEST_V2 request, byte[] data, string path)
        {
            HttpApiRequest retQuest = new HttpApiRequest();
            HttpApiResponse retResponse = new HttpApiResponse();
            retQuest.Init(request, data, false, false);
            retResponse.Init(reqQueue, request);
            path = path.Replace('/', '\\');
            if(path == "\\")
            {
                path = m_defaultFile;
            }
            var ext = Path.GetExtension(path);
            string newPath;
            if(ext == "html" || ext == "htm")
            {
                newPath = m_htmlFilePath + System.Web.HttpUtility.UrlDecode(path);
            }
            else
            {
                newPath = m_webPath+ System.Web.HttpUtility.UrlDecode(path);
            }
            if(File.Exists(newPath))
            {
                var handle = File.OpenHandle(newPath);
                if (handle.IsInvalid)
                {
                    retResponse.Response404();
                }
                else
                {
                    var fileSize = new FileInfo(newPath).Length;
                    string status;
                    ushort statusCode;
                    long startOffset;
                    long endOffset;
                    if (retQuest.ContainsHeader("Range"))
                    {
                        var range = retQuest.GetRange();
                        startOffset = Convert.ToInt64(Between(range, "=", "-"));
                        if (range.Substring(range.Length - 1, 1) == "-")
                        {
                            if(fileSize < 163840)
                            {
                                endOffset = fileSize;
                            }
                            else
                            {
                                if(startOffset < fileSize)
                                {
                                    endOffset = startOffset + 163840;
                                }
                                else
                                {
                                    endOffset = fileSize;
                                }
                            }
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
                    retResponse.SetContentRange(contentRange);
                    var typeName = ExtToContentType(ext);
                    if (typeName != "html" || typeName != "htm")
                    {
                        retResponse.SetContentType(typeName);
                    }
                    if(fileSize > 163840)
                    {
                        retResponse.SetAcceptRanges();
                    }
                    retResponse.WriteFile(handle, startOffset, endOffset - startOffset, statusCode, status);
                    handle.Close();
                }
            }
            else
            {
                retResponse.Response404();
            }
        }

        public bool Init(string serverName, string webPath = "", string htmlFilePath = "", string requestFile = "", List<string> banFile = null)
        {
            HTTPAPI_VERSION version = new HTTPAPI_VERSION();
            version.HttpApiMinorVersion = 0;
            version.HttpApiMajorVersion = 2;
            var ret = HttpInitialize(version, HTTP_INIT.HTTP_INITIALIZE_SERVER | HTTP_INIT.HTTP_INITIALIZE_CONFIG);
            if (ret != Vanara.PInvoke.Win32Error.NO_ERROR)
            {
                return false;
            }
            HTTPAPI_VERSION version2 = new HTTPAPI_VERSION();
            version2.HttpApiMinorVersion = 0;
            version2.HttpApiMajorVersion = 2;
            ret = HttpCreateServerSession(version2, out m_sessionID);
            if (ret != Vanara.PInvoke.Win32Error.NO_ERROR)
            {
                return false;
            }
            ret = HttpCreateUrlGroup(m_sessionID, out m_groupID);
            if (ret != Vanara.PInvoke.Win32Error.NO_ERROR)
            {
                return false;
            }
            ret = HttpCreateRequestQueue(version, serverName, null, 0, out m_reqQueue);
            if (ret != Vanara.PInvoke.Win32Error.NO_ERROR)
            {
                return false;
            }
            HTTP_BINDING_INFO BindingProperty = new HTTP_BINDING_INFO();
            BindingProperty.Flags.Present = true;
            BindingProperty.RequestQueueHandle = m_reqQueue;
            int bindingPropertySize = Marshal.SizeOf(typeof(HTTP_BINDING_INFO));
            nint bindingPropertyPtr = Marshal.AllocHGlobal(bindingPropertySize);
            Marshal.StructureToPtr<HTTP_BINDING_INFO>(BindingProperty, bindingPropertyPtr, false);
            ret = HttpSetUrlGroupProperty(m_groupID, HTTP_SERVER_PROPERTY.HttpServerBindingProperty, bindingPropertyPtr, (uint)bindingPropertySize);
            Marshal.FreeHGlobal(bindingPropertyPtr);
            if (ret != Vanara.PInvoke.Win32Error.NO_ERROR)
            {
                return false;
            }
           
            HTTP_TIMEOUT_LIMIT_INFO TimeoutsProperty = new HTTP_TIMEOUT_LIMIT_INFO();
            TimeoutsProperty.EntityBody = 50;
            TimeoutsProperty.Flags.Present = true;
            int timeoutsPropertySize = Marshal.SizeOf(typeof(HTTP_TIMEOUT_LIMIT_INFO));
            nint timeoutsPropertyPtr = Marshal.AllocHGlobal(timeoutsPropertySize);
            Marshal.StructureToPtr<HTTP_TIMEOUT_LIMIT_INFO>(TimeoutsProperty, timeoutsPropertyPtr, false);
            ret = HttpSetUrlGroupProperty(m_groupID, HTTP_SERVER_PROPERTY.HttpServerTimeoutsProperty, timeoutsPropertyPtr, (uint)timeoutsPropertySize);
            Marshal.FreeHGlobal(timeoutsPropertyPtr);
            if (ret != Vanara.PInvoke.Win32Error.NO_ERROR)
            {
                return false;
            }
            
            if(requestFile == "")
            {
                requestFile = "\\index.html";
            }
            m_defaultFile = requestFile;
            if(webPath == "")
            {
                webPath = System.AppDomain.CurrentDomain.SetupInformation.ApplicationBase;
            }
            if(htmlFilePath == "")
            {
                htmlFilePath = webPath;
            }
            m_webPath = webPath;
            m_htmlFilePath = htmlFilePath;
            m_banFile = banFile;
            return true;
        }

        public bool BindHttpPort(short port)
        {
            string url = "http://+:" + port.ToString() + "/";
            var ret = HttpAddUrlToUrlGroup(m_groupID, url);
            if (ret != Vanara.PInvoke.Win32Error.NO_ERROR)
            {
                return false;
            }
            return true;
        }

        private byte[] HexStringToByteArray(string s)
        {
               s = s.Replace(" ", "");
               byte[] buffer = new byte[s.Length / 2];
               for (int i = 0; i<s.Length; i += 2)
               {
                  buffer[i / 2] = (byte) Convert.ToByte(s.Substring(i, 2), 16);
               }
              return buffer;
        }

        private T ByteToStructure<T>(byte[] dataBuffer)
        {
            object structure = null;
            int size = Marshal.SizeOf(typeof(T));
            nint allocIntPtr = Marshal.AllocHGlobal(size);
            try
            {
                Marshal.Copy(dataBuffer, 0, allocIntPtr, size);
                structure = Marshal.PtrToStructure(allocIntPtr, typeof(T));
            }
            finally
            {
                Marshal.FreeHGlobal(allocIntPtr);
            }
            return (T)structure;
        }

        public bool BindHttpsPort(string host, ushort port, string pfx)
        {
            HTTP_SERVICE_CONFIG_SSL_SNI_SET configInformation = new HTTP_SERVICE_CONFIG_SSL_SNI_SET();
            configInformation.KeyDesc.Host = host;
            configInformation.KeyDesc.IpPort.ss_family = ADDRESS_FAMILY.AF_INET;
            SOCKADDR_IN sockin = new SOCKADDR_IN();
            sockin.sin_port = port;
            sockin.sin_family = ADDRESS_FAMILY.AF_INET;
            sockin.sin_addr.S_addr = inet_addr("0.0.0.0");
            configInformation.KeyDesc.IpPort = (SOCKADDR_STORAGE)sockin;
            var pfxData = HexStringToByteArray(pfx);
            nint allocIntPtr = Marshal.AllocHGlobal(pfxData.Length);
            configInformation.ParamDesc.pSslHash = allocIntPtr;
            configInformation.ParamDesc.SslHashLength = (uint)pfxData.Length;
            configInformation.ParamDesc.AppId = Guid.NewGuid();
            configInformation.ParamDesc.pSslCertStoreName = "MY";
            int configInformationSize = Marshal.SizeOf(typeof(HTTP_SERVICE_CONFIG_SSL_SNI_SET));
            nint configInformationPtr = Marshal.AllocHGlobal(configInformationSize);
            Marshal.StructureToPtr<HTTP_SERVICE_CONFIG_SSL_SNI_SET>(configInformation, configInformationPtr, false);
            HttpDeleteServiceConfiguration(IntPtr.Zero, HTTP_SERVICE_CONFIG_ID.HttpServiceConfigSSLCertInfo, configInformationPtr, (uint)configInformationSize);
            var ret = HttpSetServiceConfiguration(IntPtr.Zero, HTTP_SERVICE_CONFIG_ID.HttpServiceConfigSSLCertInfo, configInformationPtr, (uint)configInformationSize);
            Marshal.FreeHGlobal(configInformationPtr);
            Marshal.FreeHGlobal(allocIntPtr);
            if (ret != Vanara.PInvoke.Win32Error.NO_ERROR)
            {
                return false;
            }
            var url = "https://" + host + ":" + port.ToString() + "/";
            ret = HttpAddUrlToUrlGroup(m_groupID, url);
            if (ret != Vanara.PInvoke.Win32Error.NO_ERROR)
            {
                return false;
            }
            return true;
        }

        public void Subscribe(string requestPath, SubscribeProcDelegate proc)
        {
            m_SubscribeMap.Add(requestPath, proc);
        }

        public bool DelSubscribe(string path)
        {
            if(m_SubscribeMap.ContainsKey(path))
            {
                return m_SubscribeMap.Remove(path);
            }
            return false;
        }

        public void ClearAllSubscribe()
        {
            m_SubscribeMap.Clear();
        }

        public void Delay(int time)
        {
            var task = Task.Run(async delegate
            {
                await Task.Delay(time);
            });
            task.Wait();
        }

        public bool Stop()
        {
            m_start = false;
            Delay(1000);

            if (m_groupID != null)
            {
                HttpRemoveUrlFromUrlGroup(m_groupID, "");
                HttpCloseUrlGroup(m_groupID);
                m_groupID = null;
            }
            if(m_sessionID != null)
            {
                HttpCloseServerSession(m_sessionID);
                m_sessionID = null;
            }
            if(m_reqQueue != null)
            {
                HttpCloseRequestQueue(m_reqQueue);
                m_reqQueue = null;
                HttpTerminate(HTTP_INIT.HTTP_INITIALIZE_SERVER | HTTP_INIT.HTTP_INITIALIZE_CONFIG);
            }
            m_thread.Clear();
            return true;
        }

        public void Start(int threadCount)
        {
            if(m_start == false)
            {
                
                m_start = true;
                for (var index = 0; index < threadCount; index++)
                {
                    var ThreadGetHttpDataIn = new Thread(OnThreadRequestCallback);
                    ThreadGetHttpDataIn.Start();
                    m_thread.Add(ThreadGetHttpDataIn);
                }
            }
        }
        
        public bool SetTimeout(ushort connectTimeout, ushort receiveTimeout)
        {
            HTTP_SERVICE_CONFIG_TIMEOUT_SET configInformation = new HTTP_SERVICE_CONFIG_TIMEOUT_SET();
            configInformation.KeyDesc = HTTP_SERVICE_CONFIG_TIMEOUT_KEY.IdleConnectionTimeout;
            configInformation.ParamDesc = connectTimeout;
            int configInformationSize = Marshal.SizeOf(typeof(HTTP_SERVICE_CONFIG_TIMEOUT_SET));
            nint configInformationPtr = Marshal.AllocHGlobal(configInformationSize);
            Marshal.StructureToPtr<HTTP_SERVICE_CONFIG_TIMEOUT_SET>(configInformation, configInformationPtr, false);
            var ret = HttpSetServiceConfiguration(IntPtr.Zero, HTTP_SERVICE_CONFIG_ID.HttpServiceConfigTimeout, configInformationPtr, (uint)configInformationSize);
            Marshal.FreeHGlobal(configInformationPtr);
            if (ret != Vanara.PInvoke.Win32Error.NO_ERROR)
            {
                return false;
            }
           
            configInformation.KeyDesc = HTTP_SERVICE_CONFIG_TIMEOUT_KEY.HeaderWaitTimeout;
            configInformation.ParamDesc = receiveTimeout;
            configInformationSize = Marshal.SizeOf(typeof(HTTP_SERVICE_CONFIG_TIMEOUT_SET));
            configInformationPtr = Marshal.AllocHGlobal(configInformationSize);
            Marshal.StructureToPtr<HTTP_SERVICE_CONFIG_TIMEOUT_SET>(configInformation, configInformationPtr, false);
            ret = HttpSetServiceConfiguration(IntPtr.Zero, HTTP_SERVICE_CONFIG_ID.HttpServiceConfigTimeout, configInformationPtr, (uint)configInformationSize);
            Marshal.FreeHGlobal(configInformationPtr);
            if (ret != Vanara.PInvoke.Win32Error.NO_ERROR)
            {
                return false;
            }
            return true;
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct HTTP_API_REQUEST_PARAM
    {
        public string key { get; set; }
        public string value { get; set; }
    }

    public class HttpApiRequest
    {
        private HTTP_REQUEST_V2 m_request = new HTTP_REQUEST_V2();
        Dictionary<string, string> m_Headers = new Dictionary<string, string>();
        List<HTTP_API_REQUEST_PARAM> m_paramArr = new List<HTTP_API_REQUEST_PARAM>();
        byte[] m_postData = new byte[0];
        private List<string> m_headerNames = new List<string>(){"Cache-Control", "Connection", "Date", "KeepAlive",
        "Pragma", "Trailer", "Transfer-Encoding", "Upgrade", "Via", "Warning", "Allow", "Content-Length",
        "Content-Type", "Content-Encoding", "Content-Language", "Content-Location", "Content-Md5", "Content-Range",
        "Expires", "Last-Modified", "Accept", "Accept-Charset", "Accept-Encoding", "Accept-Language", "Authorization",
        "Cookie", "Expect", "From", "Host", "If-Match", "If-ModifiedSince", "If-NoneMatch", "If-Range", "If-UnmodifiedSince",
        "Max-Forwards", "Proxy-Authorization", "Referer", "Range", "Te", "Translate", "User-Agent"};

        private string UrlParsePath(string rawUrl)
        {
            var index = rawUrl.IndexOf('?');
            if (index == -1)
            {
                return rawUrl;
            }
            else
            {
                return rawUrl.Substring(0, index);
            }
        }

        private void UrlParseParam(string rawUrl)
        {
            var index = rawUrl.IndexOf('?');
            if (index == -1)
            {
                return;
            }
            var newUrl = rawUrl.Substring(index + 1, rawUrl.Length - index - 1);
            var index2 = newUrl.IndexOf('&');
            while (index2 != -1)
            {
                var part = newUrl.Substring(0, index2);
                var index3 = part.IndexOf('=');
                if (index3 != -1)
                {
                    var left = part.Substring(0, index3);
                    var right = part.Substring(index3 + 1, part.Length - index3 - 1);
                    HTTP_API_REQUEST_PARAM param = new HTTP_API_REQUEST_PARAM();
                    param.key = left;
                    param.value = right;
                    m_paramArr.Add(param);
                }
                newUrl = newUrl.Substring(index2 + 1, newUrl.Length - index2 - 1);
                index2 = newUrl.IndexOf('&');
            }
            var part2 = newUrl;
            var index4 = part2.IndexOf('=');
            if (index4 != -1)
            {
                var left = part2.Substring(0, index4);
                var right = part2.Substring(index4 + 1, part2.Length - index4 - 1);
                HTTP_API_REQUEST_PARAM param = new HTTP_API_REQUEST_PARAM();
                param.key = left;
                param.value = right;
                m_paramArr.Add(param);
            }
        }

        public void Init(HTTP_REQUEST_V2 request, byte[] data, bool parseUrlForm, bool parsePostDataForm)
        {
            m_request = request;
            m_postData = data;
            for (int i = 0; i < 40; i++)
            {
                var knownHeader = request.Headers.KnownHeaders[i];
                m_Headers.Add(m_headerNames[i], knownHeader.pRawValue);
            }
            var uknowheadercount = request.Headers.UnknownHeaderCount;
            for(int i = 0; i<uknowheadercount;i++)
            {
                m_Headers.Add(request.Headers.UnknownHeaders[i].pName, request.Headers.UnknownHeaders[i].pRawValue);
            }
            var rawUrl = request.pRawUrl;
            if(parseUrlForm)
            {
                UrlParsePath(rawUrl);
                UrlParseParam(rawUrl);
            }
            else
            {
                UrlParsePath(rawUrl);
            }
            if(parsePostDataForm)
            {
               var ct = GetContentType();
                if(ct == "application/x-www-form-urlencoded")
                {
                    var formData = Encoding.UTF8.GetString(data);
                    UrlParseParam(formData);
                }
            }
        }

        public string GetHeader(string name)
        {
            if(m_Headers.ContainsKey(name))
            {
                return m_Headers[name];
            }
            return "";
        }

        public string GetUserAgent()
        {
            return GetHeader("User-Agent");
        }

        public string GetCookie()
        {
            return GetHeader("Cookie");
        }

        public string GetContentType()
        {
            return GetHeader("ContentType");
        }

        public string GetIfNoneMatch()
        {
            return GetHeader("If-NoneMatch");
        }

        public string GetReferer()
        {
            return GetHeader("Referer");
        }

        public string GetRange()
        {
            return GetHeader("Range");
        }

        public string GetRemoteAddress()
        {
            var ret = (SOCKADDR_IN)(SOCKADDR.CreateFromStructure(m_request.Address.RemoteAddress));
            StringBuilder buf = new StringBuilder(17);
            inet_ntop(ADDRESS_FAMILY.AF_INET, ret.sin_addr, buf, 17);
            return buf.ToString();
        }

        public ushort GetRemotePort()
        {
            var ret = ((SOCKADDR_IN)m_request.Address.RemoteAddress);
            var port = ntohs(ret.sin_port);
            return port;
        }

        public byte[] GetPostData()
        {
            return m_postData;
        }

        public string GetRequestPath()
        {
            return m_request.CookedUrl.pAbsPath;
        }

        public string GetRequestHost()
        {
            return m_request.CookedUrl.pHost;
        }

        public string GetRawUrl()
        {
            return m_request.CookedUrl.pFullUrl;
        }

        public string GetParam(string keyName)
        {
            foreach(var index in m_paramArr)
            {
                if(index.key == keyName)
                {
                    return index.value;
                }
            }
            return "";
        }

        public int GetAllParam(ref List<HTTP_API_REQUEST_PARAM> arrays)
        {
            arrays = m_paramArr;
            return m_paramArr.Count;
        }

        public bool ContainsHeader(string name)
        {
            return m_Headers.ContainsKey(name);
        }

        public string GetAllHeaders()
        {
            string ret = "";
            foreach(var index in m_Headers)
            {
                ret += index.Key + ":" + index.Value + "\n";
            }
            return ret;
        }
    }

    public class HttpApiResponse
    {
        private HTTP_RESPONSE_V2 m_response = new HTTP_RESPONSE_V2();
        private SafeHREQQUEUE m_reqQueue;
        private HTTP_REQUEST_V2 m_request = new HTTP_REQUEST_V2();
        private ushort m_statusCode = 200;
        private string m_reason = "";
        private List<int> m_headerNameArr = new List<int>();
        private List<string> m_headerValueArr = new List<string>();
        private List<string> m_unknownHeaderNameArr = new List<string>();
        private List<string> m_unknownHeaderValArr = new List<string>();

        public void Init(SafeHREQQUEUE reqQueue, HTTP_REQUEST_V2 request)
        {
            m_reqQueue = reqQueue;
            m_request = request;
            m_statusCode = 200;
            m_reason = "OK";
            m_response.Headers.KnownHeaders = new HTTP_KNOWN_HEADER[41];
        }

        private void InitResponseStruct(ushort StatusCode, string Reason)
        {
            m_response.StatusCode = StatusCode;
            m_response.pReason = Reason;
            m_response.ReasonLength = (ushort)Reason.Length;
        }

        private void AddKnownHeader(int header, string value)
        {
            m_response.Headers.KnownHeaders[header].pRawValue = value;
            m_response.Headers.KnownHeaders[header].RawValueLength = (ushort)(value.Length);
        }

        private static int GetStrLength(string str)
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

        private void AddUnKnownHeader()
        {
            var count = m_unknownHeaderNameArr.Count;

            if(count>0)
            {
                List<HTTP_UNKNOWN_HEADER> unknownHeader = new List<HTTP_UNKNOWN_HEADER>();
                for (int i=0;i<count;i++)
                {
                    HTTP_UNKNOWN_HEADER index = new HTTP_UNKNOWN_HEADER();
                    index.pName = m_unknownHeaderNameArr[i];
                    index.NameLength = (ushort)m_unknownHeaderNameArr[i].Length;
                    index.pRawValue = m_unknownHeaderValArr[i];
                    index.RawValueLength = (ushort)m_unknownHeaderValArr[i].Length;
                    unknownHeader.Add(index);
                }
    
                var pUnknownHeader = Marshal.AllocHGlobal(count * Marshal.SizeOf(typeof(HTTP_UNKNOWN_HEADER)));
                long LongPtr = pUnknownHeader.ToInt64();
                for(int i=0;i<count;i++)
                {
                    IntPtr RectPtr = new IntPtr(LongPtr);
                    Marshal.StructureToPtr(unknownHeader[i], RectPtr, false); 
                    LongPtr += Marshal.SizeOf(typeof(HTTP_UNKNOWN_HEADER));
                }
                m_response.Headers.pUnknownHeaders = pUnknownHeader;
                m_response.Headers.UnknownHeaderCount = (ushort)count;
            }
        }


        public bool WriteText(string text)
        {
            InitResponseStruct(m_statusCode, m_reason);
            bool skip = false;
            for (int i = 0; i < m_headerNameArr.Count; i++)
            {
                AddKnownHeader(m_headerNameArr[i], m_headerValueArr[i]);
                if (m_headerNameArr[i] == (int)HTTP_HEADER_ID.HttpHeaderContentType)
                {
                    skip = true;
                }
            }
            if (!skip)
            {
                SetContentType("text/html; charset=gb2312");
            }
            AddUnKnownHeader();
            FROMMEMORY index = new FROMMEMORY();
            index.pBuffer = Marshal.StringToHGlobalAnsi(text);
            index.BufferLength = (uint)(GetStrLength(text));
            HTTP_DATA_CHUNK chunk = new HTTP_DATA_CHUNK();
            chunk.DataChunkType = HTTP_DATA_CHUNK_TYPE.HttpDataChunkFromMemory;
            chunk.FromMemory = index;
            var pChunkHeader = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(HTTP_DATA_CHUNK)));
            Marshal.StructureToPtr<HTTP_DATA_CHUNK>(chunk, pChunkHeader, false);
            m_response.EntityChunkCount = 1;
            m_response.pEntityChunks = pChunkHeader;
            var ret = HttpSendHttpResponse(m_reqQueue, m_request.RequestId, 0, m_response, IntPtr.Zero, out var byteSent, IntPtr.Zero, 0, IntPtr.Zero, IntPtr.Zero);
            Marshal.FreeHGlobal(pChunkHeader);
            return ret == Win32Error.NO_ERROR;
        }

        public bool WriteData(byte[] data)
        {
            FROMMEMORY index;
            index.pBuffer = Marshal.AllocHGlobal(data.Length);
            index.BufferLength = (uint)data.Length;
            InitResponseStruct(m_statusCode, m_reason);
            bool skip = false;
            for (int i = 0; i < m_headerNameArr.Count; i++)
            {
                AddKnownHeader(m_headerNameArr[i], m_headerValueArr[i]);
                if (m_headerNameArr[i] == (int)HTTP_HEADER_ID.HttpHeaderContentType)
                {
                    skip = true;
                }
            }
            if (!skip)
            {
                SetContentType("bytes/stream");
            }
            AddUnKnownHeader();
            HTTP_DATA_CHUNK chunk = new HTTP_DATA_CHUNK();
            chunk.DataChunkType = HTTP_DATA_CHUNK_TYPE.HttpDataChunkFromMemory;
            chunk.FromMemory = index;
            var pChunkHeader = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(HTTP_DATA_CHUNK)));
            Marshal.StructureToPtr<HTTP_DATA_CHUNK>(chunk, pChunkHeader, false);
            m_response.EntityChunkCount = 1;
            m_response.pEntityChunks = pChunkHeader;
            var ret = HttpSendHttpResponse(m_reqQueue, m_request.RequestId, 0, m_response, IntPtr.Zero, out var byteSent, IntPtr.Zero, 0, IntPtr.Zero, IntPtr.Zero);
            Marshal.FreeHGlobal(pChunkHeader);
            Marshal.FreeHGlobal(index.pBuffer);
            return ret == Win32Error.NO_ERROR;
        }

        public bool WriteFile(SafeFileHandle handle, long startOffset, long length, ushort statusCode, string status)
        {
            FROMFILEHANDLE index;
            index.FileHandle = handle;
            index.ByteRange.StartingOffset = (ulong)startOffset;
            index.ByteRange.Length = (ulong)length;
            InitResponseStruct(m_statusCode, m_reason);
            bool skip = false;
            for (int i = 0; i < m_headerNameArr.Count; i++)
            {
                AddKnownHeader(m_headerNameArr[i], m_headerValueArr[i]);
                if (m_headerNameArr[i] == (int)HTTP_HEADER_ID.HttpHeaderContentType)
                {
                    skip = true;
                }
            }
            if (!skip)
            {
                SetContentType("bytes");
            }
            AddUnKnownHeader();
            HTTP_DATA_CHUNK chunk = new HTTP_DATA_CHUNK();
            chunk.DataChunkType = HTTP_DATA_CHUNK_TYPE.HttpDataChunkFromFileHandle;
            chunk.FromFileHandle = index;
            var pChunkHeader = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(HTTP_DATA_CHUNK)));
            Marshal.StructureToPtr<HTTP_DATA_CHUNK>(chunk, pChunkHeader, false);
            m_response.EntityChunkCount = 1;
            m_response.pEntityChunks = pChunkHeader;
            var ret = HttpSendHttpResponse(m_reqQueue, m_request.RequestId, 0, m_response, IntPtr.Zero, out var byteSent, IntPtr.Zero, 0, IntPtr.Zero, IntPtr.Zero);
            Marshal.FreeHGlobal(pChunkHeader);
            return ret == Win32Error.NO_ERROR;
        }

        private void SetResponseHeader(int header, string value)
        {
            m_headerNameArr.Add(header);
            m_headerValueArr.Add(value);
        }
        public void SetStatusCode(ushort statusCode, string reason)
        {
            m_statusCode = statusCode;
            m_reason = reason;
        }

        public void SetAcceptRanges(string value = "bytes")
        {
            SetResponseHeader((int)HTTP_HEADER_ID.HttpHeaderAcceptRanges, value);
        }

        public void SetAge(string value = "12")
        {
            SetResponseHeader((int)HTTP_HEADER_ID.HttpHeaderAge, value);
        }

        public void SetAllow(string value = "GET, POST, HEAD")
        {
            SetResponseHeader((int)HTTP_HEADER_ID.HttpHeaderAllow, value);
        }

        public void SetCacheControl(string value = "no-cache")
        {
            SetResponseHeader((int)HTTP_HEADER_ID.HttpHeaderCacheControl, value);
        }

        public void SetContentEncoding(string value = "gzip")
        {
            SetResponseHeader((int)HTTP_HEADER_ID.HttpHeaderContentEncoding, value);
        }

        public void SetContentLanguage(string value = "en, zh")
        {
            SetResponseHeader((int)HTTP_HEADER_ID.HttpHeaderContentLanguage, value);
        }
        public void SetContentLocation(string value = "/index.html")
        {
            SetResponseHeader((int)HTTP_HEADER_ID.HttpHeaderContentLocation, value);
        }
        public void SetContentMD5(string value)
        {
            SetResponseHeader((int)HTTP_HEADER_ID.HttpHeaderContentMd5, value);
        }
        public void SetContentRange(string value)
        {
            SetResponseHeader((int)HTTP_HEADER_ID.HttpHeaderContentRange, value);
        }
        public void SetETag(string value)
        {
            SetResponseHeader((int)HTTP_HEADER_ID.HttpHeaderEtag, value);
        }
        public void SetExpires(string value)
        {
            SetResponseHeader((int)HTTP_HEADER_ID.HttpHeaderExpires, value);
        }
        public void SetLastModified(string value)
        {
            SetResponseHeader((int)HTTP_HEADER_ID.HttpHeaderLastModified, value);
        }
        public void SetLocation(string value)
        {
            SetResponseHeader((int)HTTP_HEADER_ID.HttpHeaderLocation, value);
        }
        public void SetProxyAuthenticate(string value)
        {
            SetResponseHeader((int)HTTP_HEADER_ID.HttpHeaderProxyAuthenticate, value);
        }
        public void SetRefresh(string value)
        {
            SetResponseHeader((int)HTTP_HEADER_ID.HttpHeaderReferer, value);
        }
        public void SetRetryAfter(string value)
        {
            SetResponseHeader((int)HTTP_HEADER_ID.HttpHeaderRetryAfter, value);
        }
        public void SetServer(string value)
        {
            SetResponseHeader((int)HTTP_HEADER_ID.HttpHeaderServer, value);
        }
        public void SetCookie(string value)
        {
            SetResponseHeader((int)HTTP_HEADER_ID.HttpHeaderSetCookie, value);
        }
        public void SetContentType(string value = "application/x-www-form-urlencoded")
        {
            SetResponseHeader((int)HTTP_HEADER_ID.HttpHeaderContentType, value);
        }

        public void Response404()
        {
            SetStatusCode(404, "404 Not Fount");
            SetContentType("text/html;charset=utf8");
            WriteText("404 Not Found");
        }

        public void SetCustomResponseHeader(string header, string value)
        {
            List<string> headerNames = new List<string>(){"Cache-Control", "Connection", "Date", "KeepAlive",
            "Pragma", "Trailer", "Transfer-Encoding", "Upgrade", "Via", "Warning", "Allow", "Content-Length",
            "Content-Type", "Content-Encoding", "Content-Language", "Content-Location", "Content-Md5", "Content-Range",
            "Expires", "Last-Modified", "Accept", "Accept-Charset", "Accept-Encoding", "Accept-Language", "Authorization",
            "Cookie", "Expect", "From", "Host", "If-Match", "If-ModifiedSince", "If-NoneMatch", "If-Range", "If-UnmodifiedSince",
            "Max-Forwards", "Proxy-Authorization", "Referer", "Range", "Te", "Translate", "User-Agent"};
            foreach(var index in headerNames)
            {
                if(index == header)
                {
                    return;
                }
            }
            m_unknownHeaderNameArr.Add(header);
            m_unknownHeaderValArr.Add(value);
        }
    }
}
