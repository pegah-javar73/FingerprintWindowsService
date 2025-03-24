
using System;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using System.Drawing;
using System.Drawing.Imaging;
using System.IO;
using Suprema;
using System.Text.Json;

namespace FingerprintWindowsService
{
    public class Worker : BackgroundService
    {
        private readonly ILogger<Worker> _logger;
        private HttpListener _listener;
        private UFScannerManager scannerManager;
        private UFScanner scanner;
        private byte[] lastCapturedTemplate;
        private int lastTemplateSize;

        public Worker(ILogger<Worker> logger)
        {
            _logger = logger;
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            InitializeScanner();

            _listener = new HttpListener();
            _listener.Prefixes.Add("http://localhost:6001/");
            _listener.Start();
            _logger.LogInformation("✅ HTTP Listener started on http://localhost:6001/");

            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    var context = await _listener.GetContextAsync();
                    _ = Task.Run(() => ProcessRequest(context));
                }
                catch (Exception ex)
                {
                    _logger.LogError($"⚠️ Listener Exception: {ex.Message}");
                }
            }
        }

        private void ProcessRequest(HttpListenerContext context)
        {
            context.Response.AddHeader("Access-Control-Allow-Origin", "*");
            context.Response.AddHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
            context.Response.AddHeader("Access-Control-Allow-Headers", "Content-Type");

            if (context.Request.HttpMethod == "OPTIONS")
            {
                context.Response.StatusCode = 200;
                context.Response.Close();
                return;
            }

            if (context.Request.HttpMethod == "POST" && context.Request.Url.AbsolutePath == "/match")
            {
                HandleMatchRequest(context);
                return;
            }

            if (context.Request.Url.AbsolutePath != "/capture")
            {
                context.Response.StatusCode = 404;
                context.Response.Close();
                _logger.LogWarning($"❌ Invalid endpoint requested: {context.Request.Url.AbsolutePath}");
                return;
            }

            CaptureFingerprint(context);
        }

        private void CaptureFingerprint(HttpListenerContext context)
        {
            try
            {
                if (scanner == null)
                {
                    _logger.LogError("❌ Scanner not initialized.");
                    context.Response.StatusCode = 500;
                    context.Response.Close();
                    return;
                }

                _logger.LogInformation("👆 لطفاً انگشت خود را روی دستگاه قرار دهید...");
                var captureStatus = scanner.CaptureSingleImage();

                if (captureStatus != UFS_STATUS.OK)
                {
                    _logger.LogError($"❌ CaptureSingleImage failed: {captureStatus}");
                    context.Response.StatusCode = 500;
                    context.Response.Close();
                    return;
                }

                var imageStatus = scanner.GetCaptureImageBuffer(out Bitmap fingerprintBitmap, out int resolution);
                if (imageStatus == UFS_STATUS.OK)
                {
                    lastCapturedTemplate = new byte[512];
                    var extractStatus = scanner.Extract(lastCapturedTemplate, out lastTemplateSize, out int quality);

                    if (extractStatus != UFS_STATUS.OK)
                    {
                        _logger.LogError($"❌ Extract failed with status: {extractStatus}");
                        context.Response.StatusCode = 500;
                        context.Response.Close();
                        return;
                    }

                    using (var ms = new MemoryStream())
                    {
                        fingerprintBitmap.Save(ms, ImageFormat.Png);
                        string base64Image = Convert.ToBase64String(ms.ToArray());
                        byte[] responseBytes = System.Text.Encoding.UTF8.GetBytes(base64Image);

                        context.Response.ContentType = "text/plain";
                        context.Response.ContentLength64 = responseBytes.Length;
                        context.Response.OutputStream.Write(responseBytes, 0, responseBytes.Length);
                        context.Response.OutputStream.Close();

                        _logger.LogInformation("✅ اثر انگشت دریافت و template ذخیره شد.");
                    }
                }
                else
                {
                    _logger.LogError($"❌ Failed to get capture buffer: {imageStatus}");
                    context.Response.StatusCode = 500;
                    context.Response.Close();
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"❌ Exception in CaptureFingerprint: {ex.Message}");
                context.Response.StatusCode = 500;
                context.Response.Close();
            }
        }
        //--for match 
        private void HandleMatchRequest(HttpListenerContext context)
        {
            try
            {
                context.Response.AddHeader("Access-Control-Allow-Origin", "*");
                context.Response.AddHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
                context.Response.AddHeader("Access-Control-Allow-Headers", "Content-Type");

                using (var reader = new StreamReader(context.Request.InputStream))
                {
                    var json = reader.ReadToEnd();
                    var data = JsonSerializer.Deserialize<MatchRequest>(json);

                    var incomingTemplate = Convert.FromBase64String(data.Base64Template);

                    if (scanner == null)
                    {
                        _logger.LogError("❌ اسکنر پیدا نشد.");
                        context.Response.StatusCode = 500;
                        context.Response.Close();
                        return;
                    }

                    _logger.LogInformation("👆 لطفاً انگشت خود را روی دستگاه قرار دهید برای تطابق...");

                    // شروع اسکن
                    var captureStatus = scanner.CaptureSingleImage();
                    if (captureStatus != UFS_STATUS.OK)
                    {
                        _logger.LogError($"❌ CaptureSingleImage failed: {captureStatus}");
                        context.Response.StatusCode = 500;
                        context.Response.Close();
                        return;
                    }

                    // گرفتن تصویر و تبدیل به template
                    var imageStatus = scanner.GetCaptureImageBuffer(out Bitmap liveFingerprintBitmap, out int resolution);
                    if (imageStatus != UFS_STATUS.OK)
                    {
                        _logger.LogError($"❌ گرفتن تصویر ناموفق بود: {imageStatus}");
                        context.Response.StatusCode = 500;
                        context.Response.Close();
                        return;
                    }

                    // استخراج template از تصویر زنده
                    byte[] liveTemplate = new byte[512];
                    var extractStatus = scanner.Extract(liveTemplate, out int liveTemplateSize, out int liveQuality);
                    if (extractStatus != UFS_STATUS.OK)
                    {
                        _logger.LogError($"❌ Extract برای اثر انگشت زنده شکست خورد: {extractStatus}");
                        context.Response.StatusCode = 500;
                        context.Response.Close();
                        return;
                    }

                    // مقایسه با UFMatcher
                    UFMatcher matcher = new UFMatcher();
                    bool verifySuccess;
                    var verifyStatus = matcher.Verify(
                        incomingTemplate,
                        incomingTemplate.Length,
                        liveTemplate,
                        liveTemplateSize,
                        out verifySuccess
                    );

                    string result = (verifyStatus == UFM_STATUS.OK)
                        ? "✅ اثر انگشت با نمونه ارسال شده مطابقت دارد."
                        : "❌ اثر انگشت تطابق ندارد.";

                    byte[] responseBytes = System.Text.Encoding.UTF8.GetBytes(result);
                    context.Response.ContentType = "text/plain";
                    context.Response.ContentLength64 = responseBytes.Length;
                    context.Response.OutputStream.Write(responseBytes, 0, responseBytes.Length);
                    context.Response.OutputStream.Close();

                    _logger.LogInformation(result);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError($"❌ خطا در HandleMatchRequest: {ex.Message}");
                context.Response.StatusCode = 500;
                context.Response.Close();
            }
        }

        private void InitializeScanner()
        {
            try
            {
                scannerManager = new UFScannerManager(null);
                scannerManager.Init();
                _logger.LogInformation("✅ اسکنر آماده شد.");

                if (scannerManager.Scanners.Count > 0)
                {
                    scanner = scannerManager.Scanners[0];
                    _logger.LogInformation("✅ اسکنر متصل شد.");
                }
                else
                {
                    _logger.LogError("⚠ هیچ اسکنری پیدا نشد.");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError("❌ Error initializing scanner: " + ex.Message);
            }
        }

        public override void Dispose()
        {
            _listener?.Stop();
            _listener?.Close();
            base.Dispose();
        }

        private class MatchRequest
        {
            public string Base64Template { get; set; }
        }
    }
}
