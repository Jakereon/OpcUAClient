using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Opc.Ua;
using Opc.Ua.Client;
using Opc.Ua.Configuration;
using OpcUAClient;

namespace OpcUaClient
{
    /// <summary>
    /// Represents an OPC UA session with functionality for session renewal, monitoring data changes, and server communication.
    /// </summary>
    public partial class OPCSession : INotifyPropertyChanged, IDisposable
    {
        #region Properties

        // Implement INotifyPropertyChanged for Settings if needed for binding
        private Settings _settings;
        public Settings Settings
        {
            get { return _settings; }
            set
            {
                if (_settings != value)
                {
                    _settings = value;
                    OnPropertyChanged(nameof(Settings));
                }
            }
        }

        private Session OPCConnection { get; set; }
        private DateTime LastTimeSessionRenewed { get; set; }
        private DateTime LastTimeOPCServerFoundAlive { get; set; }
        private CancellationTokenSource _cancellationTokenSource;
        private Task _renewalTask;
        private bool _disposed;
        private readonly List<Subscription> _subscriptions = new List<Subscription>();

        // User Access Properties
        public bool InitialisationCompleted;
        public List<Tag> TagList;
        public bool Connected
        {
            get
            {
                return OPCConnection != null && OPCConnection.Connected;
            }
        }

        // Events
        public event EventHandler<string> ConnectionLost;
        public event EventHandler<TagValueChangedEventArgs> TagChanged;
        public event PropertyChangedEventHandler PropertyChanged;

        protected void OnPropertyChanged(string propertyName)
        {
            var handler = PropertyChanged;
            if (handler != null)
                handler(this, new PropertyChangedEventArgs(propertyName));
        }

        #endregion

        /// <summary>
        /// Initializes a new instance of the <see cref="OPCSession"/> class using the provided <paramref name="settings"/>.
        /// 
        /// This constructor performs the following steps:
        /// 1. Validates that all critical configuration fields are present and non-empty.
        /// 2. Stores the settings and initializes internal structures (e.g., <see cref="TagList"/>).
        /// 3. Calls <c>InitializeOPCUAClient()</c> to establish a connection with the OPC UA server.
        ///
        /// The <paramref name="settings"/> object must include the following properties:
        ///
        /// <list type="bullet">
        ///   <item>
        ///     <term><c>ServerAddress</c></term>
        ///     <description>
        ///     The hostname or IP address of the OPC UA server (e.g., <c>"broomco-90yvst3"</c>). 
        ///     This is combined with the port and path to form the full endpoint URI.
        ///     </description>
        ///   </item>
        ///   <item>
        ///     <term><c>ServerPort</c></term>
        ///     <description>
        ///     The port number used to connect to the OPC UA server (e.g., <c>"62640"</c>).
        ///     This must match the port the server is actively listening on.
        ///     </description>
        ///   </item>
        ///   <item>
        ///     <term><c>MyApplicationName</c></term>
        ///     <description>
        ///     A unique name for this client application. It is used when registering the client
        ///     with the OPC UA server and appears in session logs and diagnostics.
        ///     </description>
        ///   </item>
        ///   <item>
        ///     <term><c>EndpointPath</c> (optional)</term>
        ///     <description>
        ///     The additional endpoint path (e.g., <c>"/IntegrationObjects/ServerSimulator"</c>) that completes the full URI. 
        ///     This may vary depending on the server implementation. If not explicitly included in the settings,
        ///     the default endpoint path will be used.
        ///     </description>
        ///   </item>
        ///   <item>
        ///     <term><c>UseAnonymousAuth</c></term>
        ///     <description>
        ///     Indicates whether the client should use anonymous authentication (true) or credentials (false).
        ///     If false, ensure that username and password fields are populated in the settings.
        ///     </description>
        ///   </item>
        /// </list>
        ///
        /// <para>
        /// Example endpoint URI constructed from these settings:
        /// <c>opc.tcp://{ServerAddress}:{ServerPort}{EndpointPath}</c>
        /// </para>
        ///
        /// </summary>
        /// <param name="settings">The OPC UA connection settings used to establish and configure the client session.</param>
        /// <exception cref="OPCUAException">
        /// Thrown if required settings are missing, or if an error occurs during session initialization.
        /// </exception>
        /// <param name="settings">The OPC UA connection settings.</param>
        /// <exception cref="OPCUAException">Thrown if settings are invalid or session initialization fails.</exception>
        public OPCSession(Settings settings)
        {
            try
            {
                if (settings == null)
                    throw new ArgumentNullException(nameof(settings), "Settings cannot be null when initializing OPCSession.");

                if (string.IsNullOrWhiteSpace(settings.ServerAddress))
                    throw new OPCUAException("ServerAddress is missing in provided Settings object.", "Constructor");

                if (string.IsNullOrWhiteSpace(settings.ServerPort))
                    throw new OPCUAException("ServerPort is missing in provided Settings object.", "Constructor");

                if (string.IsNullOrWhiteSpace(settings.MyApplicationName))
                    throw new OPCUAException("MyApplicationName is missing in provided Settings object.", "Constructor");

                Settings = settings;
                TagList = new List<Tag>();
                LastTimeOPCServerFoundAlive = DateTime.Now;

                try
                {
                    InitializeOPCUAClient();
                }
                catch (Exception ex)
                {
                    throw new OPCUAException($"OPC UA client initialization failed: {ex.Message}", "Constructor->InitializeOPCUAClient", ex);
                }
            }
            catch (ArgumentNullException ex)
            {
                throw new OPCUAException($"Constructor received null Settings: {ex.Message}", "Constructor", ex);
            }
            catch (OPCUAException)
            {
                throw;
            }
            catch (Exception ex)
            {
                throw new OPCUAException($"Unexpected error during OPCSession construction: {ex.Message}", "Constructor", ex);
            }
        }

        #region Metrics

        public TimeSpan SessionUptime => DateTime.Now - LastTimeSessionRenewed;

        /// <summary>
        /// Executes an operation with automatic retries on transient errors.
        /// </summary>
        /// <param name="operation">The operation to execute.</param>
        /// <param name="retryCount">The number of retries to attempt.</param>
        /// <returns>True if the operation succeeds; otherwise, false.</returns>
        public async Task<bool> ExecuteWithRetry(Func<Task> operation, int retryCount = 3)
        {
            for (int attempt = 1; attempt <= retryCount; attempt++)
            {
                try
                {
                    await operation();
                    return true;
                }
                catch (Exception ex) when (IsTransientError(ex))
                {
                    throw new OPCUAException($"Attempt {attempt} failed: {ex.Message}");
                    await Task.Delay(1000); // Backoff delay
                }
            }
            return false;
        }

        /// <summary>
        /// Determines whether an exception is a transient error.
        /// </summary>
        /// <param name="ex">The exception to check.</param>
        /// <returns>True if the error is transient; otherwise, false.</returns>
        private bool IsTransientError(Exception ex)
        {
            return ex is ServiceResultException sre && sre.StatusCode == StatusCodes.BadTimeout;
        }

        public event EventHandler SessionConnected;
        public event EventHandler SessionDisconnected;

        /// <summary>
        /// Raise session connected event.
        /// </summary>
        private void OnSessionConnected()
        {
            SessionConnected?.Invoke(this, EventArgs.Empty);
        }

        /// <summary>
        /// Raise session disconnected event.
        /// </summary>
        private void OnSessionDisconnected()
        {
            SessionDisconnected?.Invoke(this, EventArgs.Empty);
        }

        /// <summary>
        /// Gets the total uptime of the OPC session.
        /// </summary>
        public TimeSpan TotalUptime => OPCConnection != null ? DateTime.Now - LastTimeSessionRenewed : TimeSpan.Zero;

        private int _totalRequestsSent;
        private int _totalResponsesReceived;

        /// <summary>
        /// Gets the total number of requests sent to the OPC server.
        /// </summary>
        public int TotalRequestsSent => _totalRequestsSent;

        /// <summary>
        /// Gets the total number of responses received from the OPC server.
        /// </summary>
        public int TotalResponsesReceived => _totalResponsesReceived;

        /// <summary>
        /// Increments the request counter.
        /// </summary>
        private void IncrementRequestCount()
        {
            _totalRequestsSent++;
        }

        /// <summary>
        /// Increments the response counter.
        /// </summary>
        private void IncrementResponseCount()
        {
            _totalResponsesReceived++;
        }

        private TimeSpan _totalResponseTime = TimeSpan.Zero;
        private int _responseCount = 0;

        /// <summary>
        /// Gets the average response time for OPC requests.
        /// </summary>
        public TimeSpan AverageResponseTime => _responseCount > 0
            ? TimeSpan.FromMilliseconds(_totalResponseTime.TotalMilliseconds / _responseCount)
            : TimeSpan.Zero;

        /// <summary>
        /// Records the time taken for a response.
        /// </summary>
        /// <param name="responseTime">The time taken for the response.</param>
        private void RecordResponseTime(TimeSpan responseTime)
        {
            _totalResponseTime += responseTime;
            _responseCount++;
        }

        private int _errorCount;

        /// <summary>
        /// Gets the total number of errors encountered during the session.
        /// </summary>
        public int TotalErrors => _errorCount;

        /// <summary>
        /// Records an error in the session.
        /// </summary>
        private void RecordError()
        {
            _errorCount++;
        }

        private DateTime _lastSuccessfulOperation;

        /// <summary>
        /// Gets the timestamp of the last successful operation.
        /// </summary>
        public DateTime LastSuccessfulOperation => _lastSuccessfulOperation;

        /// <summary>
        /// Updates the timestamp for the last successful operation.
        /// </summary>
        private void UpdateLastSuccessfulOperation()
        {
            _lastSuccessfulOperation = DateTime.Now;
        }

        /// <summary>
        /// Gets the detailed status of the OPC connection.
        /// </summary>
        public string ConnectionStatus
        {
            get
            {
                if (OPCConnection == null)
                    return "Not connected";

                if (!OPCConnection.Connected)
                    return "Disconnected";

                return $"Connected since {LastTimeSessionRenewed}, uptime: {TotalUptime}";
            }
        }

        private Dictionary<string, DateTime> _tagUpdateTimes = new();

        /// <summary>
        /// Records the update time for a specific tag.
        /// </summary>
        /// <param name="tag">The tag being updated.</param>
        private void RecordTagUpdate(Tag tag)
        {
            _tagUpdateTimes[tag.DisplayName] = DateTime.Now;
        }

        /// <summary>
        /// Gets the update rate (in seconds) for a specific tag.
        /// </summary>
        /// <param name="tag">The tag to check.</param>
        /// <returns>The update rate in seconds, or -1 if no updates have occurred.</returns>
        public double GetTagUpdateRate(Tag tag)
        {
            if (_tagUpdateTimes.TryGetValue(tag.DisplayName, out DateTime lastUpdate))
            {
                return (DateTime.Now - lastUpdate).TotalSeconds;
            }
            return -1; // Tag has not been updated yet
        }

        private int _reconnectionAttempts;

        /// <summary>
        /// Gets the total number of reconnection attempts made during the session.
        /// </summary>
        public int TotalReconnectionAttempts => _reconnectionAttempts;

        /// <summary>
        /// Increments the reconnection attempt counter.
        /// </summary>
        private void IncrementReconnectionAttempts()
        {
            _reconnectionAttempts++;
        }

        #endregion

        #region Connect / Disconenct / Renew

        /// <summary>
        /// Initializes the OPC UA client, establishes a session with the server, performs certificate checks,
        /// selects the endpoint, and subscribes to data changes.
        /// </summary>
        /// <remarks>
        /// This method must be called before any read or write operations are performed.
        /// It creates and opens an OPC UA session with the specified server settings, and sets up keep-alive and subscriptions.
        /// </remarks>
        /// <exception cref="OPCUAException">
        /// Thrown when any part of the initialization process fails, including:
        /// <list type="bullet">
        /// <item><description>Missing or invalid <see cref="Settings"/> object.</description></item>
        /// <item><description>Application configuration or certificate setup failure.</description></item>
        /// <item><description>Endpoint selection or session creation failure.</description></item>
        /// <item><description>Keep-alive monitoring or data subscription errors.</description></item>
        /// </list>
        /// </exception>
        /// <example>
        /// <code>
        /// var settings = new Settings
        /// {
        ///     ServerAddress = "localhost",
        ///     ServerPort = "4840",
        ///     ServerPath = "MyServer",
        ///     MyApplicationName = "MyOpcClient",
        ///     SecurityEnabled = false
        /// };
        /// var session = new OPCSession(settings);
        /// session.InitializeOPCUAClient();
        /// </code>
        /// </example>
        /// <seealso cref="OPCSession"/>
        /// <seealso cref="Settings"/>
        public void InitializeOPCUAClient()
        {
            try
            {
                if (Settings == null)
                {
                    throw new OPCUAException("Settings object is null. Cannot initialize OPC UA client.", "Initialization");
                }

                if (string.IsNullOrWhiteSpace(Settings.ServerAddress))
                {
                    throw new OPCUAException("ServerAddress is missing in Settings.", "Initialization");
                }

                if (string.IsNullOrWhiteSpace(Settings.ServerPort))
                {
                    throw new OPCUAException("ServerPort is missing in Settings.", "Initialization");
                }

                if (string.IsNullOrWhiteSpace(Settings.MyApplicationName))
                {
                    throw new OPCUAException("MyApplicationName is not set in Settings.", "Initialization");
                }

                if (OPCConnection?.Connected == true)
                {
                    //throw new OPCUAException("OPC UA session already active — skipping reinitialization.", "Initialization");
                }

                Debug.WriteLine("Creating application configuration...");
                ApplicationConfiguration config;
                try
                {
                    config = CreateApplicationConfiguration();
                }
                catch (Exception ex)
                {
                    throw new OPCUAException($"Failed to create application configuration: {ex.Message}", "CreateConfiguration", ex);
                }

                var application = new ApplicationInstance
                {
                    ApplicationName = Settings.MyApplicationName,
                    ApplicationType = ApplicationType.Client,
                    ApplicationConfiguration = config
                };

                try
                {
                    Debug.WriteLine("Checking application certificate...");
                    application.CheckApplicationInstanceCertificate(false, 2048).GetAwaiter().GetResult();
                }
                catch (Exception ex)
                {
                    throw new OPCUAException($"Certificate check failed: {ex.Message}", "CertificateValidation", ex);
                }

                string endpointUrl = string.IsNullOrWhiteSpace(Settings.ServerPath)
                    ? $"opc.tcp://{Settings.ServerAddress}:{Settings.ServerPort}"
                    : $"opc.tcp://{Settings.ServerAddress}:{Settings.ServerPort}/{Settings.ServerPath.Trim('/')}";

                EndpointDescription selectedEndpoint;
                try
                {
                    Debug.WriteLine($"Selecting endpoint: {endpointUrl}");
                    selectedEndpoint = CoreClientUtils.SelectEndpoint(endpointUrl, useSecurity: Settings.SecurityEnabled);
                    if (selectedEndpoint == null)
                        throw new Exception("CoreClientUtils.SelectEndpoint returned null.");
                }
                catch (Exception ex)
                {
                    throw new OPCUAException($"Failed to select endpoint at '{endpointUrl}': {ex.Message}", "EndpointSelection", ex);
                }

                UserIdentity identity;

                try
                {
                    identity = new UserIdentity(); // anonymous
                }
                catch (Exception ex)
                {
                    throw new OPCUAException("Failed to create anonymous UserIdentity.", "UserIdentity", ex);
                }

                try
                {
                    Debug.WriteLine("Creating OPC UA session...");
                    OPCConnection = Session.Create(
                        config,
                        new ConfiguredEndpoint(null, selectedEndpoint, EndpointConfiguration.Create(config)),
                        false,
                        Settings.MyApplicationName,
                        60000,
                        identity,
                        null
                    ).GetAwaiter().GetResult();
                }
                catch (Exception ex)
                {
                    throw new OPCUAException($"Failed to create OPC UA session: {ex.Message}", "SessionCreate", ex);
                }

                if (OPCConnection == null || !OPCConnection.Connected)
                {
                    throw new OPCUAException("Session was created but is not connected.", "SessionVerification");
                }

                try
                {
                    Debug.WriteLine("Initializing KeepAlive monitoring...");
                    InitializeKeepAliveMonitoring();
                }
                catch (Exception ex)
                {
                    throw new OPCUAException($"Failed to initialize KeepAlive monitoring: {ex.Message}", "KeepAliveInit", ex);
                }

                Debug.WriteLine("OPC UA client initialized successfully.");
            }
            catch (OPCUAException)
            {
                throw; // Rethrow known exceptions as-is
            }
            catch (Exception ex)
            {
                throw new OPCUAException($"Unexpected error during OPC UA client initialization: {ex.Message}", "InitializeOPCUAClient", ex);
            }
        }

        /// <summary>
        /// Creates and validates the OPC UA application configuration.
        /// Throws detailed OPCUAException if creation fails.
        /// </summary>
        /// <returns>Validated <see cref="ApplicationConfiguration"/> object.</returns>
        private ApplicationConfiguration CreateApplicationConfiguration()
        {
            try
            {
                // Basic sanity checks on required settings
                if (Settings == null)
                    throw new OPCUAException("Settings is null.", "CreateApplicationConfiguration");
                if (string.IsNullOrWhiteSpace(Settings.MyApplicationName))
                    throw new OPCUAException("Missing MyApplicationName in Settings.", "CreateApplicationConfiguration");
                if (string.IsNullOrWhiteSpace(Settings.ServerAddress))
                    throw new OPCUAException("Missing ServerAddress in Settings.", "CreateApplicationConfiguration");

                // Build base configuration
                var config = new ApplicationConfiguration
                {
                    ApplicationName = Settings.MyApplicationName,
                    ApplicationUri = Utils.Format("urn:{0}:{1}", Settings.ServerAddress, Settings.MyApplicationName),
                    ApplicationType = ApplicationType.Client,

                    SecurityConfiguration = new SecurityConfiguration
                    {
                        ApplicationCertificate = new CertificateIdentifier
                        {
                            StoreType = "Directory",
                            StorePath = @"%CommonApplicationData%\OPC Foundation\CertificateStores\MachineDefault",
                            SubjectName = Utils.Format("CN={0}, DC={1}", Settings.MyApplicationName, Settings.ServerAddress)
                        },
                        TrustedIssuerCertificates = new CertificateTrustList
                        {
                            StoreType = "Directory",
                            StorePath = @"%CommonApplicationData%\OPC Foundation\CertificateStores\UA Certificate Authorities"
                        },
                        TrustedPeerCertificates = new CertificateTrustList
                        {
                            StoreType = "Directory",
                            StorePath = @"%CommonApplicationData%\OPC Foundation\CertificateStores\UA Applications"
                        },
                        RejectedCertificateStore = new CertificateTrustList
                        {
                            StoreType = "Directory",
                            StorePath = @"%CommonApplicationData%\OPC Foundation\CertificateStores\RejectedCertificates"
                        },
                        AutoAcceptUntrustedCertificates = true,
                        AddAppCertToTrustedStore = true
                    },

                    TransportConfigurations = new TransportConfigurationCollection(),
                    TransportQuotas = new TransportQuotas { OperationTimeout = 15000 },
                    ClientConfiguration = new ClientConfiguration { DefaultSessionTimeout = 60000 },
                    TraceConfiguration = new TraceConfiguration()
                };

                // Validate and prepare to accept untrusted certs if enabled
                try
                {
                    config.Validate(ApplicationType.Client).GetAwaiter().GetResult();
                }
                catch (Exception ex)
                {
                    throw new OPCUAException("Failed to validate OPC UA configuration.", "CreateApplicationConfiguration", ex);
                }

                if (config.SecurityConfiguration.AutoAcceptUntrustedCertificates)
                {
                    config.CertificateValidator.CertificateValidation += (s, e) =>
                    {
                        e.Accept = (e.Error.StatusCode == StatusCodes.BadCertificateUntrusted);
                    };
                }

                return config;
            }
            catch (OPCUAException) { throw; }
            catch (Exception ex)
            {
                throw new OPCUAException("Unexpected failure during configuration creation.", "CreateApplicationConfiguration", ex);
            }
        }

        /// <summary>
        /// Checks if the connected OPC UA server is responsive by reading the standard server time node (i=2258).
        /// </summary>
        /// <returns>
        /// <c>true</c> if the server responds with a good status code; otherwise, <c>false</c>.
        /// </returns>
        /// <exception cref="OPCUAException">
        /// Thrown if an unexpected error occurs during the health check operation.
        /// </exception>
        public bool IsServerAlive()
        {
            try
            {
                if (OPCConnection == null)
                {
                    throw new OPCUAException("OPC UA session is not initialized.", "IsServerAlive");
                }

                if (!OPCConnection.Connected)
                {
                    throw new OPCUAException("OPC UA session is not connected.", "IsServerAlive");
                }

                try
                {
                    // Use NodeId 2258 for Server_ServerStatus_CurrentTime
                    var nodeId = new NodeId(2258);
                    var dataValue = OPCConnection.ReadValue(nodeId);

                    if (dataValue == null)
                    {
                        throw new OPCUAException("Received null response when reading the server status node.", "IsServerAlive", "i=2258");
                    }

                    if (!StatusCode.IsGood(dataValue.StatusCode))
                    {
                        throw new OPCUAException($"Server returned non-Good status: {dataValue.StatusCode}", "IsServerAlive", "i=2258");
                    }

                    return true;
                }
                catch (ServiceResultException sre)
                {
                    throw new OPCUAException($"Service-level exception during server health check: {sre.Message}", "IsServerAlive", "i=2258", sre);
                }
                catch (Exception ex)
                {
                    throw new OPCUAException($"Unexpected error during server health check: {ex.Message}", "IsServerAlive", "i=2258", ex);
                }
            }
            catch (OPCUAException)
            {
                // Optional: You could log the exception here if you don't want to throw it.
                return false;
            }
        }

        /// <summary>
        /// Sets up KeepAlive monitoring for the current OPC UA session.
        /// </summary>
        private void InitializeKeepAliveMonitoring()
        {
            try
            {
                if (OPCConnection == null)
                {
                    throw new OPCUAException("OPC UA session is null. Cannot initialize KeepAlive monitoring.", "InitializeKeepAliveMonitoring");
                }

                if (!OPCConnection.Connected)
                {
                    throw new OPCUAException("OPC UA session is not connected. KeepAlive setup aborted.", "InitializeKeepAliveMonitoring");
                }

                OPCConnection.KeepAlive -= OnKeepAlive; // Avoid duplicate handlers
                OPCConnection.KeepAlive += OnKeepAlive;
            }
            catch (OPCUAException)
            {
                throw;
            }
            catch (Exception ex)
            {
                throw new OPCUAException($"Unexpected error during KeepAlive monitoring setup: {ex.Message}", "InitializeKeepAliveMonitoring", ex);
            }
        }

        /// <summary>
        /// Handles KeepAlive events from the OPC UA session.
        /// Updates the last successful ping timestamp or triggers a connection recovery sequence upon failure.
        /// </summary>
        /// <param name="sender">The OPC UA session object.</param>
        /// <param name="e">The <see cref="KeepAliveEventArgs"/> containing connection status details.</param>
        /// <exception cref="OPCUAException">
        /// Thrown for communication failures or internal processing exceptions during KeepAlive monitoring.
        /// </exception>
        private void OnKeepAlive(object sender, KeepAliveEventArgs e)
        {
            try
            {
                if (e == null)
                {
                    throw new OPCUAException("KeepAlive event argument is null.", "OnKeepAlive");
                }

                if (sender is not Session session)
                {
                    throw new OPCUAException("KeepAlive sender is not a valid OPC UA Session.", "OnKeepAlive");
                }

                Debug.WriteLine($"[KeepAlive] Received KeepAlive status: {e.Status}");

                if (!ServiceResult.IsGood(e.Status))
                {
                    Debug.WriteLine($"[KeepAlive] Connection issue detected. Status: {e.Status}");

                    try
                    {
                        HandleConnectionLoss();
                    }
                    catch (OPCUAException ex)
                    {
                        throw new OPCUAException($"HandleConnectionLoss failed after bad KeepAlive: {ex.Message}", "OnKeepAlive/HandleConnectionLoss", ex);
                    }
                    catch (Exception ex)
                    {
                        throw new OPCUAException($"Unexpected error during connection recovery: {ex.Message}", "OnKeepAlive/HandleConnectionLoss", ex);
                    }

                    throw new OPCUAException($"KeepAlive error received from server: {e.Status}", "OnKeepAlive");
                }

                try
                {
                    LastTimeOPCServerFoundAlive = DateTime.Now;
                    Debug.WriteLine($"[KeepAlive] Server responded successfully at {LastTimeOPCServerFoundAlive}");
                }
                catch (Exception ex)
                {
                    throw new OPCUAException($"Failed to update KeepAlive timestamp: {ex.Message}", "OnKeepAlive/UpdateTimestamp", ex);
                }
            }
            catch (OPCUAException)
            {
                throw; // Preserve rich context
            }
            catch (Exception ex)
            {
                throw new OPCUAException($"Unexpected error during KeepAlive event handling: {ex.Message}", "OnKeepAlive/Unhandled", ex);
            }
        }

        /// <summary>
        /// Handles unexpected OPC UA connection loss by closing and disposing the session,
        /// and optionally reinitializing the client. Excessively validated and exception-wrapped.
        /// </summary>
        /// <exception cref="OPCUAException">
        /// Thrown for any errors during cleanup or reinitialization steps.
        /// Includes nested exception information and contextual operation names.
        /// </exception>
        private void HandleConnectionLoss()
        {
            try
            {
                Debug.WriteLine("[ConnectionLoss] Starting connection recovery sequence...");

                // Defensive null check before cleanup
                if (OPCConnection == null)
                {
                    throw new OPCUAException("OPCConnection is null during connection loss handling.", "HandleConnectionLoss");
                }

                try
                {
                    Debug.WriteLine("[ConnectionLoss] Attempting to close OPC UA session...");
                    OPCConnection.Close();
                    Debug.WriteLine("[ConnectionLoss] Session closed successfully.");
                }
                catch (Exception ex)
                {
                    throw new OPCUAException($"Failed to close OPC UA session: {ex.Message}", "HandleConnectionLoss/Close", ex);
                }

                try
                {
                    Debug.WriteLine("[ConnectionLoss] Disposing OPC UA session...");
                    OPCConnection.Dispose();
                    Debug.WriteLine("[ConnectionLoss] Session disposed successfully.");
                }
                catch (Exception ex)
                {
                    throw new OPCUAException($"Failed to dispose OPC UA session: {ex.Message}", "HandleConnectionLoss/Dispose", ex);
                }

                OPCConnection = null;

                // Optional: Attempt reconnection
                try
                {
                    Debug.WriteLine("[ConnectionLoss] Attempting to reinitialize client...");
                    // InitializeOPCUAClient(); // Uncomment if automatic reconnection is desired
                    Debug.WriteLine("[ConnectionLoss] Reinitialization step completed.");
                }
                catch (OPCUAException ex)
                {
                    throw new OPCUAException($"Reinitialization failed: {ex.Message}", "HandleConnectionLoss/Reinit", ex);
                }
                catch (Exception ex)
                {
                    throw new OPCUAException($"Unexpected error during reinitialization: {ex.Message}", "HandleConnectionLoss/Reinit", ex);
                }

                Debug.WriteLine("[ConnectionLoss] Connection loss handling complete.");
            }
            catch (OPCUAException)
            {
                throw; // Preserve structured exception with context
            }
            catch (Exception ex)
            {
                throw new OPCUAException($"Unhandled exception during connection loss handling: {ex.Message}", "HandleConnectionLoss", ex);
            }
        }

        /// <summary>
        /// Public Dispose method to clean up OPC UA session resources.
        /// Invokes managed cleanup and suppresses finalization.
        /// </summary>
        /// <exception cref="OPCUAException">Thrown if disposal fails at any stage.</exception>
        public void Dispose()
        {
            try
            {
                Dispose(true);
                GC.SuppressFinalize(this);
            }
            catch (Exception ex)
            {
                throw new OPCUAException($"Unexpected error during Dispose(): {ex.Message}", "Dispose", ex);
            }
        }

        /// <summary>
        /// Core disposal method that handles resource cleanup depending on the disposing flag.
        /// Disposes managed objects and marks the object as disposed.
        /// </summary>
        /// <param name="disposing">Indicates whether to dispose managed resources.</param>
        /// <exception cref="OPCUAException">Thrown if any managed resource fails to dispose.</exception>
        protected virtual void Dispose(bool disposing)
        {
            if (_disposed)
                return;

            if (disposing)
            {
                try
                {
                    Debug.WriteLine("Disposing OPC UA subscriptions...");
                    DisposeAllSubscriptions();
                }
                catch (Exception ex)
                {
                    throw new OPCUAException($"Failed to dispose subscriptions: {ex.Message}", "Dispose/Subscriptions", ex);
                }

                try
                {
                    if (OPCConnection != null)
                    {
                        Debug.WriteLine("Closing OPC UA session...");
                        OPCConnection.Close();
                        OPCConnection.Dispose();
                        OPCConnection = null;
                    }
                }
                catch (Exception ex)
                {
                    throw new OPCUAException($"Failed to close or dispose OPCConnection: {ex.Message}", "Dispose/OPCConnection", ex);
                }

                try
                {
                    if (_cancellationTokenSource != null)
                    {
                        Debug.WriteLine("Cancelling and disposing cancellation token...");
                        _cancellationTokenSource.Cancel();
                        _cancellationTokenSource.Dispose();
                        _cancellationTokenSource = null;
                    }
                }
                catch (Exception ex)
                {
                    throw new OPCUAException($"Failed to dispose cancellation token: {ex.Message}", "Dispose/CancellationToken", ex);
                }
            }

            _disposed = true;
        }

        /// <summary>
        /// Iterates through and safely disposes all active OPC UA subscriptions.
        /// </summary>
        /// <exception cref="OPCUAException">Throws detailed errors per subscription if disposal fails.</exception>
        private void DisposeAllSubscriptions()
        {
            if (_subscriptions == null || _subscriptions.Count == 0)
            {
                Debug.WriteLine("No subscriptions to dispose.");
                return;
            }

            foreach (var sub in _subscriptions)
            {
                try
                {
                    Debug.WriteLine($"Disposing subscription: {sub.DisplayName}...");
                    sub.Delete(true);                         // Remove monitored items
                    OPCConnection?.RemoveSubscription(sub);   // Unregister from session
                    sub.Dispose();                            // Dispose local instance
                }
                catch (Exception ex)
                {
                    throw new OPCUAException(
                        $"Failed to dispose subscription '{sub.DisplayName}': {ex.Message}",
                        "DisposeAllSubscriptions",
                        sub.DisplayName);
                }
            }

            _subscriptions.Clear();
            Debug.WriteLine("All subscriptions disposed.");
        }

        #endregion

        #region TagHandling

        /// <summary>
        /// Reads the value of a specific OPC UA node and attempts to cast it to the specified type.
        /// </summary>
        /// <typeparam name="T">The expected return type of the node value.</typeparam>
        /// <param name="tag">The tag containing the NodeID to read.</param>
        /// <returns>The value read from the OPC UA server, cast to type <typeparamref name="T"/>.</returns>
        /// <exception cref="OPCUAException">
        /// Thrown if the tag is null, the NodeID is invalid, the value is null, 
        /// or if reading fails due to session or conversion errors.
        /// </exception>
        public T ReadNodeValue<T>(Tag tag)
        {
            try
            {
                if (tag == null)
                    throw new OPCUAException("Tag object is null.", "ReadNodeValue");

                if (string.IsNullOrWhiteSpace(tag.NodeID))
                    throw new OPCUAException("Tag.NodeID is null or empty.", "ReadNodeValue", tag?.DisplayName);

                if (OPCConnection == null || !OPCConnection.Connected)
                    throw new OPCUAException("OPC UA session is not connected.", "ReadNodeValue", tag.NodeID);

                Debug.WriteLine($"Reading Node: {tag.DisplayName} ({tag.NodeID})");
                var nodeId = new NodeId(tag.NodeID);
                var dataValue = OPCConnection.ReadValue(nodeId);

                if (dataValue == null)
                    throw new OPCUAException("Read returned null DataValue.", "ReadNodeValue", tag.NodeID);

                if (dataValue.Value == null)
                    throw new OPCUAException($"Node '{tag.DisplayName}' returned a null value.", "ReadNodeValue", tag.NodeID);

                return (T)Convert.ChangeType(dataValue.Value, typeof(T));
            }
            catch (InvalidCastException ex)
            {
                throw new OPCUAException($"Failed to cast value from node '{tag?.DisplayName}' to type {typeof(T).Name}: {ex.Message}", "ReadNodeValue", tag?.NodeID);
            }
            catch (ServiceResultException ex)
            {
                throw new OPCUAException($"OPC UA service error while reading node '{tag?.DisplayName}': {ex.Message}", "ReadNodeValue", ex);
            }
            catch (Exception ex)
            {
                throw new OPCUAException($"Unexpected error while reading node '{tag?.DisplayName}': {ex.Message}", "ReadNodeValue", ex);
            }
        }

        /// <summary>
        /// Writes a value to a specified OPC UA node.
        /// </summary>
        /// <param name="tag">The tag containing the NodeID to write to.</param>
        /// <param name="value">The value to write to the node.</param>
        /// <exception cref="OPCUAException">
        /// Thrown if the tag or connection is invalid, the NodeID is missing,
        /// or if the server fails to accept the written value.
        /// </exception>
        public void WriteNodeValue(Tag tag, object value)
        {
            try
            {
                if (tag == null)
                    throw new OPCUAException("Tag object is null.", "WriteNodeValue");

                if (string.IsNullOrWhiteSpace(tag.NodeID))
                    throw new OPCUAException("Tag.NodeID is null or empty.", "WriteNodeValue", tag?.DisplayName);

                if (OPCConnection == null || !OPCConnection.Connected)
                    throw new OPCUAException("OPC UA session is not connected.", "WriteNodeValue", tag?.NodeID);

                var nodeId = NodeId.Parse(tag.NodeID);

                var writeValue = new WriteValue
                {
                    NodeId = nodeId,
                    AttributeId = Attributes.Value,
                    Value = new DataValue(new Variant(value))
                };

                var writeCollection = new WriteValueCollection { writeValue };

                OPCConnection.Write(
                    null,
                    writeCollection,
                    out StatusCodeCollection results,
                    out DiagnosticInfoCollection diagnosticInfos);

                if (results == null || results.Count == 0)
                    throw new OPCUAException("Write operation returned no status results.", "WriteNodeValue", tag.NodeID);

                if (StatusCode.IsBad(results[0]))
                    throw new OPCUAException($"Write failed: {results[0]}", "WriteNodeValue", tag.NodeID);

                Debug.WriteLine($"Successfully wrote value '{value}' to node '{tag.DisplayName}'");
            }
            catch (ServiceResultException ex)
            {
                throw new OPCUAException($"OPC UA service error during write: {ex.Message}", "WriteNodeValue", ex);
            }
            catch (Exception ex)
            {
                throw new OPCUAException($"Unexpected error during write to node '{tag?.DisplayName}': {ex.Message}", "WriteNodeValue", ex);
            }
        }

        /// <summary>
        /// Subscribes to OPC UA data changes for all tags in the <see cref="TagList"/>.
        /// Creates monitored items for each tag and registers them with the server.
        /// </summary>
        /// <exception cref="OPCUAException">
        /// Thrown if the session is not connected, or if any part of the subscription process fails.
        /// </exception>
        public void SubscribeToDataChanges()
        {
            try
            {
                if (OPCConnection == null || !OPCConnection.Connected)
                    throw new OPCUAException("OPC UA session is not connected.", "SubscribeToDataChanges");

                Debug.WriteLine("[Subscribe] Creating subscription...");

                var subscription = new Subscription(OPCConnection.DefaultSubscription)
                {
                    DisplayName = $"Sub_{DateTime.Now:HHmmss}",
                    PublishingEnabled = true,
                    PublishingInterval = 1000
                };

                foreach (var tag in TagList)
                {
                    try
                    {
                        if (string.IsNullOrWhiteSpace(tag.NodeID))
                            throw new OPCUAException("Tag.NodeID is null or empty.", "SubscribeToDataChanges", tag?.DisplayName);

                        Debug.WriteLine($"[Subscribe] Adding monitored item: {tag.DisplayName} ({tag.NodeID})");

                        var monitoredItem = new MonitoredItem(subscription.DefaultItem)
                        {
                            StartNodeId = tag.NodeID,
                            AttributeId = Attributes.Value,
                            DisplayName = tag.DisplayName,
                            SamplingInterval = 1000
                        };

                        monitoredItem.Notification += OnTagValueChange;
                        subscription.AddItem(monitoredItem);
                    }
                    catch (Exception ex)
                    {
                        throw new OPCUAException($"Failed to create monitored item for tag '{tag?.DisplayName}': {ex.Message}", "SubscribeToDataChanges", tag?.NodeID);
                    }
                }

                try
                {
                    subscription.ApplyChanges();
                }
                catch (Exception ex)
                {
                    throw new OPCUAException("Failed to apply subscription changes.", "SubscribeToDataChanges", ex);
                }

                try
                {
                    OPCConnection.AddSubscription(subscription);
                    subscription.Create();
                }
                catch (Exception ex)
                {
                    throw new OPCUAException("Failed to create and register subscription with the OPC server.", "SubscribeToDataChanges", ex);
                }

                _subscriptions.Add(subscription);
                Debug.WriteLine($"[Subscribe] Subscription created successfully with {subscription.MonitoredItemCount} items.");
            }
            catch (OPCUAException)
            {
                throw;
            }
            catch (Exception ex)
            {
                throw new OPCUAException($"Unexpected error during subscription setup: {ex.Message}", "SubscribeToDataChanges", ex);
            }
        }

        /// <summary>
        /// Subscribes to OPC UA data changes for a single tag.
        /// Creates a monitored item and registers it with the server.
        /// </summary>
        /// <param name="tag">The tag to subscribe to.</param>
        /// <exception cref="OPCUAException">
        /// Thrown if the session is not connected, the tag is invalid, or the subscription fails.
        /// </exception>
        public void SubscribeToTag(Tag tag)
        {
            try
            {
                if (OPCConnection == null || !OPCConnection.Connected)
                    throw new OPCUAException("OPC UA session is not connected.", "SubscribeToTag");

                if (tag == null)
                    throw new OPCUAException("Tag is null.", "SubscribeToTag");

                if (string.IsNullOrWhiteSpace(tag.NodeID))
                    throw new OPCUAException("Tag.NodeID is null or empty.", "SubscribeToTag", tag.DisplayName);

                Debug.WriteLine($"[Subscribe] Creating subscription for: {tag.DisplayName} ({tag.NodeID})");

                var subscription = new Subscription(OPCConnection.DefaultSubscription)
                {
                    DisplayName = $"Sub_{tag.DisplayName}_{DateTime.Now:HHmmss}",
                    PublishingEnabled = true,
                    PublishingInterval = 1000
                };

                var monitoredItem = new MonitoredItem(subscription.DefaultItem)
                {
                    StartNodeId = tag.NodeID,
                    AttributeId = Attributes.Value,
                    DisplayName = tag.DisplayName,
                    SamplingInterval = 1000
                };

                monitoredItem.Notification += OnTagValueChange;
                subscription.AddItem(monitoredItem);

                subscription.ApplyChanges();

                OPCConnection.AddSubscription(subscription);
                subscription.Create();

                _subscriptions.Add(subscription);
                Debug.WriteLine($"[Subscribe] Subscription created for tag: {tag.DisplayName}");
            }
            catch (OPCUAException)
            {
                throw;
            }
            catch (Exception ex)
            {
                throw new OPCUAException($"Unexpected error during subscription setup for tag '{tag?.DisplayName}': {ex.Message}", "SubscribeToTag", ex);
            }
        }


        /// <summary>
        /// Handles data change notifications for monitored items.
        /// Updates internal tag state and triggers <see cref="TagChanged"/> events.
        /// </summary>
        /// <param name="item">The monitored item that triggered the event.</param>
        /// <param name="e">The event args containing updated values.</param>
        private void OnTagValueChange(MonitoredItem item, MonitoredItemNotificationEventArgs e)
        {
            try
            {
                if (item == null || e == null)
                    throw new OPCUAException("Invalid event arguments in OnTagValueChange.", "OnTagValueChange");

                foreach (var value in item.DequeueValues())
                {
                    try
                    {
                        var tag = TagList.FirstOrDefault(t => t.DisplayName == item.DisplayName);
                        if (tag == null)
                            throw new OPCUAException($"No matching tag found for monitored item: {item.DisplayName}", "OnTagValueChange");

                        tag.CurrentValue = value.Value?.ToString();
                        tag.LastUpdatedTime = DateTime.Now;
                        tag.LastSourceTimeStamp = value.SourceTimestamp.ToLocalTime();
                        tag.StatusCode = value.StatusCode.ToString();

                        TagChanged?.Invoke(this, new TagValueChangedEventArgs(tag.DisplayName, tag.CurrentValue, tag.LastUpdatedTime));
                    }
                    catch (Exception ex)
                    {
                        throw new OPCUAException($"Error processing value for tag '{item.DisplayName}': {ex.Message}", "OnTagValueChange", ex);
                    }
                }
            }
            catch (OPCUAException)
            {
                throw;
            }
            catch (Exception ex)
            {
                throw new OPCUAException($"Unhandled error in OnTagValueChange: {ex.Message}", "OnTagValueChange", ex);
            }
        }

        #endregion
    }
}
