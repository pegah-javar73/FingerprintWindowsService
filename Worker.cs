
using System;
using System.Drawing;
using System.IO;
using System.Net;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using DentalWindowsApp;
using Microsoft.Extensions.Hosting;
using Newtonsoft.Json;
using Suprema;

namespace FingerprintWindowsService
{
    public class Worker : BackgroundService
    {
        private UFScannerManager scannerManager;
        private UFScanner scanner;
        private UFMatcher matcher;
        private byte[] storedTemplate;

        public Worker()
        {
            try
            {
                DllLoader.LoadSupremaDlls();
                Log("✅ DLL ها بارگذاری شدند.");
            }
            catch (Exception ex)
            {
                Log("❌ خطا در بارگذاری DLL: " + ex.Message);
            }

            scannerManager = new UFScannerManager(null);
            scannerManager.Init();

            if (scannerManager.Scanners.Count > 0)
            {
                scanner = scannerManager.Scanners[0];
                matcher = new UFMatcher();
                Log("📷 اسکنر آماده است.");
            }
            else
            {
                Log("❌ اسکنری یافت نشد.");
            }
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            var httpListener = new HttpListener();
            httpListener.Prefixes.Add("http://localhost:6001/");

            httpListener.Start();
            Log("🌐 Listening on http://localhost:6001/");

            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    var context = await httpListener.GetContextAsync();
                    var request = context.Request;
                    var response = context.Response;

                    // هدرهای CORS
                    response.Headers.Add("Access-Control-Allow-Origin", "*");
                    response.Headers.Add("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
                    response.Headers.Add("Access-Control-Allow-Headers", "Content-Type");

                    // پاسخ به درخواست OPTIONS
                    if (request.HttpMethod == "OPTIONS")
                    {
                        response.StatusCode = (int)HttpStatusCode.OK;
                        response.Close();
                        continue;
                    }

                    string resultJson = string.Empty;

                    switch (request.Url.AbsolutePath.ToLower())
                    {
                        case "/capture":
                            resultJson = Capture();
                            break;

                        case "/match":
                            resultJson = Match();
                            break;
                        case "/matchtemplates":
                            using (var reader = new StreamReader(request.InputStream, request.ContentEncoding))
                            {
                                var body = await reader.ReadToEndAsync();
                                resultJson = MatchTemplates(body);
                            }
                            break;

                        default:
                            response.StatusCode = (int)HttpStatusCode.NotFound;
                            resultJson = CreateResponse(false, null, "آدرس یافت نشد.");
                            break;
                    }

                    await SendResponse(response, resultJson);
                }
                catch (Exception ex)
                {
                    Log("❌ خطا در پردازش درخواست: " + ex.Message);
                }
            }

            httpListener.Stop();
        }
        private string Capture()
        {
            if (scanner == null)
                return CreateResponse(false, null, "اسکنر آماده نیست.");

            var status = scanner.CaptureSingleImage();
            if (status == UFS_STATUS.OK)
            {
                status = scanner.GetCaptureImageBuffer(out Bitmap bitmap, out int resolution);
                if (status == UFS_STATUS.OK)
                {
                    byte[] template = GetFingerprintTemplate();
                    if (template != null)
                    {
                        storedTemplate = template;
                        // ❗ برگرداندن مستقیم byte[] به عنوان data (نه base64)
                        return CreateResponse(true, template, "اثر انگشت ثبت شد.");
                    }
                }
            }

            return CreateResponse(false, null, "خطا در ثبت اثر انگشت.");
        }

        private string Match()
        {
            if (scanner == null || storedTemplate == null)
                return CreateResponse(false, null, "ابتدا اثر انگشت را ذخیره کنید.");

            var status = scanner.CaptureSingleImage();
            if (status == UFS_STATUS.OK)
            {
                status = scanner.GetCaptureImageBuffer(out Bitmap bitmap, out int resolution);
                if (status == UFS_STATUS.OK)
                {
                    byte[] newTemplate = GetFingerprintTemplate();
                    if (newTemplate != null)
                    {
                        bool matched;
                        var verifyStatus = matcher.Verify(
                            storedTemplate, storedTemplate.Length,
                            newTemplate, newTemplate.Length,
                            out matched
                        );

                        if (verifyStatus == UFM_STATUS.OK)
                        {
                            if (matched)
                                return CreateResponse(true, "Fingerprint matched.", "اثر انگشت مطابقت دارد ✅");
                            else
                                return CreateResponse(false, "Fingerprint does not match.", "اثر انگشت مطابقت ندارد ❌");
                        }

                        return CreateResponse(false, null, "خطا در تطبیق: " + verifyStatus);
                    }
                }
            }

            return CreateResponse(false, null, "خطا در دریافت اثر انگشت.");
        }

        private byte[] GetFingerprintTemplate()
        {
            try
            {
                byte[] buffer = new byte[1024];
                int size, quality;

                var status = scanner.Extract(buffer, out size, out quality);

                if (status == UFS_STATUS.OK)
                {
                    byte[] actualTemplate = new byte[size];
                    Array.Copy(buffer, actualTemplate, size);
                    return actualTemplate;
                }

                return null;
            }
            catch (Exception ex)
            {
                Log("❌ خطا در استخراج Template: " + ex.Message);
                return null;
            }
        }

        private string CreateResponse(bool success, object data, string message)
        {
            var obj = new
            {
                success = success,
                data = data,
                message = message
            };

            return JsonConvert.SerializeObject(obj);
        }

        private async Task SendResponse(HttpListenerResponse response, string json)
        {
            byte[] buffer = Encoding.UTF8.GetBytes(json);
            response.ContentType = "application/json";
            response.ContentEncoding = Encoding.UTF8;
            response.StatusCode = (int)HttpStatusCode.OK;
            await response.OutputStream.WriteAsync(buffer, 0, buffer.Length);
            response.Close();
        }
        private string MatchTemplates(string requestBody)
        {
            try
            {
                var matchRequest = JsonConvert.DeserializeObject<TemplateMatchRequest>(requestBody);

                if (matchRequest.StoredTemplate == null || matchRequest.NewTemplate == null)
                {
                    return CreateResponse(false, null, "یکی از قالب‌ها خالی است.");
                }

                bool isMatched;
                var status = matcher.Verify(
                    matchRequest.StoredTemplate, matchRequest.StoredTemplate.Length,
                    matchRequest.NewTemplate, matchRequest.NewTemplate.Length,
                    out isMatched
                );

                if (status == UFM_STATUS.OK)
                {
                    return isMatched
                        ? CreateResponse(true, "Templates matched.", "اثر انگشت‌ها تطابق دارند ✅")
                        : CreateResponse(false, "Templates do not match.", "اثر انگشت‌ها تطابق ندارند ❌");
                }

                return CreateResponse(false, null, "خطا در تطبیق: " + status);
            }
            catch (Exception ex)
            {
                Log("❌ خطا در MatchTemplates: " + ex.Message);
                return CreateResponse(false, null, "خطای سرور در پردازش قالب‌ها.");
            }
        }


        private void Log(string message)
        {
            File.AppendAllText("log.txt", $"{DateTime.Now}: {message}{Environment.NewLine}");
        }
        public class TemplateMatchRequest
        {
            public byte[] StoredTemplate { get; set; }
            public byte[] NewTemplate { get; set; }
        }
    }
}
