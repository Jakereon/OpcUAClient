using System.ComponentModel;
using System.Diagnostics;
using Opc.Ua;
using Opc.Ua.Client;
using Opc.Ua.Configuration;
using OpcUAClient;

namespace OpcUaClient
{
    /// <summary>
    /// OPCSession provides a high-level abstraction for managing OPC UA client sessions in .NET applications,
    /// including secure session creation, connection management, automatic session renewal, tag monitoring
    /// (subscriptions), reading and writing tag values, and fine-grained event-driven data change handling.
    ///
    /// <para><b>Key Features:</b></para>
    /// <list type="bullet">
    ///   <item>OPC UA session management (connect/disconnect/renew/dispose)</item>
    ///   <item>Certificate and security configuration, with optional anonymous or credential authentication</item>
    ///   <item>Efficient subscription handling: monitors multiple tags in a single subscription</item>
    ///   <item>Per-tag event notifications via <see cref="Tag.ValueChanged"/></item>
    ///   <item>Global tag change notifications via <see cref="TagChanged"/> event</item>
    ///   <item>Robust error and connection loss handling</item>
    ///   <item>Automatic resource cleanup and metrics (uptime, error counts, etc.)</item>
    /// </list>
    ///
    /// <para><b>Basic Usage Example:</b></para>
    /// <code>
    /// // 1. Create OPC UA connection settings (adjust to match your server)
    /// var settings = new Settings
    /// {
    ///     ServerAddress = "broomcoKWDEV01.hdna.hd.lan",
    ///     ServerPort = "49320",
    ///     ServerPath = "broomcoKWDEV01",
    ///     MyApplicationName = "MyOpcUaClient",
    ///     SecurityEnabled = false,
    ///     SessionRenewalRequired = true
    /// };
    ///
    /// // 2. Create OPCSession
    /// var opcSession = new OPCSession(settings);
    ///
    /// // 3. Add your tags (example: all from CEL_FBC_COUNTER_01.Controller)
    /// opcSession.TagList.Add(new Tag("FabricColor", "ns=2;s=CEL_FBC_COUNTER_01.Controller.FabricColor"));
    /// opcSession.TagList.Add(new Tag("Message", "ns=2;s=CEL_FBC_COUNTER_01.Controller.Message"));
    /// opcSession.TagList.Add(new Tag("RemainingCellCount", "ns=2;s=CEL_FBC_COUNTER_01.Controller.RemainingCellCount"));
    /// opcSession.TagList.Add(new Tag("RequestType", "ns=2;s=CEL_FBC_COUNTER_01.Controller.RequestType"));
    /// opcSession.TagList.Add(new Tag("Status", "ns=2;s=CEL_FBC_COUNTER_01.Controller.Status"));
    /// opcSession.TagList.Add(new Tag("TotalCellCount", "ns=2;s=CEL_FBC_COUNTER_01.Controller.TotalCellCount"));
    /// opcSession.TagList.Add(new Tag("UnitCellCount", "ns=2;s=CEL_FBC_COUNTER_01.Controller.UnitCellCount"));
    ///
    /// // 4. Register tag-specific logic using ValueChanged events (per tag)
    /// var statusTag = opcSession.TagList.First(t => t.DisplayName == "Status");
    /// statusTag.ValueChanged += tag =>
    /// {
    ///     if (tag.CurrentValue == null)
    ///         Console.WriteLine("Status tag is null.");
    ///     else
    ///         Console.WriteLine($"Status changed: {tag.CurrentValue}");
    /// };
    ///
    /// // 5. (Optional) Register global handler for all tag changes
    /// opcSession.TagChanged += (sender, e) =>
    ///     Console.WriteLine($"Tag [{e.DisplayName}] value changed: {e.NewValue}");
    ///
    /// // 6. Connect and subscribe to data changes
    /// opcSession.InitializeOPCUAClient();
    /// opcSession.SubscribeToDataChanges();
    ///
    /// // 7. Read and write tag values as needed
    /// string msg = opcSession.ReadNodeValue<string>(statusTag);
    /// opcSession.WriteNodeValue(statusTag, "NewStatusValue");
    /// </code>
    ///
    /// <para><b>Handling Nulls and Errors:</b></para>
    /// <para>Tag values may be <c>null</c> if the server provides no value or the node is empty. This is handled gracefully; always check for <c>null</c> before using tag values. All public methods throw <see cref="OPCUAException"/> with rich context on error.</para>
    ///
    /// <para><b>Thread Safety:</b> This class is not thread-safe for writes; synchronize external calls as needed.</para>
    ///
    /// <para><b>See Also:</b> <see cref="Tag"/>, <see cref="Settings"/>, <see cref="TagValueChangedEventArgs"/></para>
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

                try
                {
                    StartConnectionMonitor();
                }
                catch (Exception)
                {

                    throw;
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
                throw;
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


        /// <summary> raise an event when the connection is lost
        private void StartConnectionMonitor()
        {

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
        //public T ReadNodeValue<T>(Tag tag)
        //{
        //    try
        //    {
        //        if (tag == null)
        //            throw new OPCUAException("Tag object is null.", "ReadNodeValue");

        //        if (string.IsNullOrWhiteSpace(tag.NodeID))
        //            throw new OPCUAException("Tag.NodeID is null or empty.", "ReadNodeValue", tag?.DisplayName);

        //        if (OPCConnection == null || !OPCConnection.Connected)
        //            throw new OPCUAException("OPC UA session is not connected.", "ReadNodeValue", tag.NodeID);

        //        Debug.WriteLine($"Reading Node: {tag.DisplayName} ({tag.NodeID})");
        //        var nodeId = new NodeId(tag.NodeID);
        //        var dataValue = OPCConnection.ReadValue(nodeId);

        //        if (dataValue == null)
        //            return default; // Instead of throwing

        //        if (dataValue.Value == null)
        //            return default; // Allow null

        //        return (T)Convert.ChangeType(dataValue.Value, typeof(T));
        //    }
        //    catch (InvalidCastException ex)
        //    {
        //        throw new OPCUAException($"Failed to cast value from node '{tag?.DisplayName}' to type {typeof(T).Name}: {ex.Message}", "ReadNodeValue", tag?.NodeID);
        //    }
        //    catch (ServiceResultException ex)
        //    {
        //        throw new OPCUAException($"OPC UA service error while reading node '{tag?.DisplayName}': {ex.Message}", "ReadNodeValue", ex);
        //    }
        //    catch (Exception ex)
        //    {
        //        throw new OPCUAException($"Unexpected error while reading node '{tag?.DisplayName}': {ex.Message}", "ReadNodeValue", ex);
        //    }
        //}

        ///// <summary>
        ///// Writes a value to a specified OPC UA node.
        ///// </summary>
        ///// <param name="tag">The tag containing the NodeID to write to.</param>
        ///// <param name="value">The value to write to the node.</param>
        ///// <exception cref="OPCUAException">
        ///// Thrown if the tag or connection is invalid, the NodeID is missing,
        ///// or if the server fails to accept the written value.
        ///// </exception>
        //public void WriteNodeValue(Tag tag, object value)
        //{
        //    try
        //    {
        //        if (tag == null)
        //            throw new OPCUAException("Tag object is null.", "WriteNodeValue");

        //        if (string.IsNullOrWhiteSpace(tag.NodeID))
        //            throw new OPCUAException("Tag.NodeID is null or empty.", "WriteNodeValue", tag?.DisplayName);

        //        if (OPCConnection == null || !OPCConnection.Connected)
        //            throw new OPCUAException("OPC UA session is not connected.", "WriteNodeValue", tag?.NodeID);

        //        var nodeId = NodeId.Parse(tag.NodeID);

        //        var writeValue = new WriteValue
        //        {
        //            NodeId = nodeId,
        //            AttributeId = Attributes.Value,
        //            Value = new DataValue(new Variant(value))
        //        };

        //        var writeCollection = new WriteValueCollection { writeValue };

        //        OPCConnection.Write(
        //            null,
        //            writeCollection,
        //            out StatusCodeCollection results,
        //            out DiagnosticInfoCollection diagnosticInfos);

        //        if (results == null || results.Count == 0)
        //            throw new OPCUAException("Write operation returned no status results.", "WriteNodeValue", tag.NodeID);

        //        if (StatusCode.IsBad(results[0]))
        //            throw new OPCUAException($"Write failed: {results[0]}", "WriteNodeValue", tag.NodeID);

        //        Debug.WriteLine($"Successfully wrote value '{value}' to node '{tag.DisplayName}'");
        //    }
        //    catch (ServiceResultException ex)
        //    {
        //        throw new OPCUAException($"OPC UA service error during write: {ex.Message}", "WriteNodeValue", ex);
        //    }
        //    catch (Exception ex)
        //    {
        //        throw new OPCUAException($"Unexpected error during write to node '{tag?.DisplayName}': {ex.Message}", "WriteNodeValue", ex);
        //    }
        //}

        /// <summary>
        /// Subscribes to OPC UA data changes for all tags in the <see cref="TagList"/>.
        /// Creates monitored items for each tag and registers them with the server.
        /// </summary>
        /// <exception cref="OPCUAException">
        /// Thrown if the session is not connected, or if any part of the subscription process fails.
        /// </exception>
        //public void SubscribeToDataChanges()
        //{
        //    try
        //    {
        //        if (OPCConnection == null || !OPCConnection.Connected)
        //            throw new OPCUAException("OPC UA session is not connected.", "SubscribeToDataChanges");

        //        Debug.WriteLine("[Subscribe] Creating subscription...");

        //        var subscription = new Subscription(OPCConnection.DefaultSubscription)
        //        {
        //            DisplayName = $"Sub_{DateTime.Now:HHmmss}",
        //            PublishingEnabled = true,
        //            PublishingInterval = 1000
        //        };

        //        foreach (var tag in TagList)
        //        {
        //            try
        //            {
        //                if (string.IsNullOrWhiteSpace(tag.NodeID))
        //                    throw new OPCUAException("Tag.NodeID is null or empty.", "SubscribeToDataChanges", tag?.DisplayName);

        //                Debug.WriteLine($"[Subscribe] Adding monitored item: {tag.DisplayName} ({tag.NodeID})");

        //                var monitoredItem = new MonitoredItem(subscription.DefaultItem)
        //                {
        //                    StartNodeId = tag.NodeID,
        //                    AttributeId = Attributes.Value,
        //                    DisplayName = tag.DisplayName,
        //                    SamplingInterval = 1000
        //                };

        //                monitoredItem.Notification += OnTagValueChange;
        //                subscription.AddItem(monitoredItem);
        //            }
        //            catch (Exception ex)
        //            {
        //                throw new OPCUAException($"Failed to create monitored item for tag '{tag?.DisplayName}': {ex.Message}", "SubscribeToDataChanges", tag?.NodeID);
        //            }
        //        }

        //        try
        //        {
        //            // The correct order: Add, Create, THEN ApplyChanges!
        //            OPCConnection.AddSubscription(subscription);
        //            subscription.Create();
        //            subscription.ApplyChanges();
        //        }
        //        catch (Exception ex)
        //        {
        //            throw new OPCUAException("Failed to create and register subscription with the OPC server.", "SubscribeToDataChanges", ex);
        //        }

        //        _subscriptions.Add(subscription);
        //        Debug.WriteLine($"[Subscribe] Subscription created successfully with {subscription.MonitoredItemCount} items.");
        //    }
        //    catch (OPCUAException)
        //    {
        //        throw;
        //    }
        //    catch (Exception ex)
        //    {
        //        throw new OPCUAException($"Unexpected error during subscription setup: {ex.Message}", "SubscribeToDataChanges", ex);
        //    }
        //}

        ///// <summary>
        ///// Handles OPC UA data change notifications for all monitored items (tags).
        ///// 
        ///// This method is triggered by the OPC UA stack whenever a value change is reported for any monitored tag.
        ///// For each data change notification:
        /////   - Locates the corresponding <see cref="Tag"/> object in <see cref="TagList"/> by matching <see cref="DisplayName"/>.
        /////   - Updates the <see cref="Tag"/>'s value, timestamp, source timestamp, and status code.
        /////   - Invokes the per-tag <see cref="Tag.ValueChanged"/> event, allowing consumers to handle tag-specific logic directly.
        /////   - Optionally, also raises a session-level <see cref="TagChanged"/> event for general listeners.
        ///// 
        ///// <para><b>Per-tag event usage:</b> By subscribing to the <see cref="Tag.ValueChanged"/> event on individual tags,
        ///// consumers can register separate callback functions for each tag, enabling tag-specific processing or UI updates.
        ///// </para>
        ///// 
        ///// <para><b>Example usage:</b><code>
        ///// // 1. Create Tag objects and subscribe to ValueChanged event
        ///// var temperatureTag = new Tag { DisplayName = "Temperature", NodeID = "ns=2;s=Temperature" };
        ///// temperatureTag.ValueChanged += tag =>
        ///// {
        /////     Console.WriteLine($@"Temperature changed! New value: {tag.CurrentValue}, at {tag.LastUpdatedTime}");
        /////     // Custom logic here, e.g., alert if too high.
        ///// };
        ///// 
        ///// var pressureTag = new Tag { DisplayName = "Pressure", NodeID = "ns=2;s=Pressure" };
        ///// pressureTag.ValueChanged += tag =>
        ///// {
        /////     Console.WriteLine($@"Pressure update: {tag.CurrentValue}");
        /////     // More custom logic...
        ///// };
        ///// 
        ///// // 2. Add tags to your OPCSession.TagList (before subscribing)
        ///// mySession.TagList.Add(temperatureTag);
        ///// mySession.TagList.Add(pressureTag);
        ///// 
        ///// // 3. Subscribe to data changes for all tags (this sets up monitoring)
        ///// mySession.SubscribeToDataChanges();
        ///// 
        ///// // 4. (Optionally) Listen for the session-wide event if you want to handle all tags together
        ///// mySession.TagChanged += (sender, e) =>
        ///// {
        /////     Console.WriteLine($@"Tag [{e.DisplayName}] changed to {e.NewValue}");
        ///// };
        ///// </code></para>
        ///// 
        ///// <para><b>Notes:</b>
        ///// - Make sure to add tags to <see cref="TagList"/> and subscribe to their <see cref="ValueChanged"/> event <b>before</b> calling <see cref="SubscribeToDataChanges"/>.
        ///// - If no handler is registered for a tag, value changes will not trigger tag-specific logic but will still update the tag object and trigger the global event if used.
        ///// </para>
        ///// 
        ///// <exception cref="OPCUAException">
        ///// Thrown if monitored item or event args are null, or if the tag cannot be found in <see cref="TagList"/>.
        ///// </exception>
        //private void OnTagValueChange(MonitoredItem item, MonitoredItemNotificationEventArgs e)
        //{
        //    try
        //    {
        //        if (item == null || e == null)
        //            throw new OPCUAException("Invalid event arguments in OnTagValueChange.", "OnTagValueChange");

        //        foreach (var value in item.DequeueValues())
        //        {
        //            try
        //            {
        //                var tag = TagList.FirstOrDefault(t => t.DisplayName == item.DisplayName);
        //                if (tag == null)
        //                    throw new OPCUAException($"No matching tag found for monitored item: {item.DisplayName}", "OnTagValueChange");

        //                tag.CurrentValue = value.Value != null ? value.Value.ToString() : null;
        //                tag.LastUpdatedTime = DateTime.Now;
        //                tag.LastSourceTimeStamp = value.SourceTimestamp.ToLocalTime();
        //                tag.StatusCode = value.StatusCode.ToString();

        //                // Raise the per-tag event
        //                tag.RaiseValueChanged();

        //                // Optionally, still fire the overall TagChanged event if you want to support both
        //                TagChanged?.Invoke(this, new TagValueChangedEventArgs(tag.DisplayName, tag.CurrentValue, tag.LastUpdatedTime));
        //            }
        //            catch (Exception ex)
        //            {
        //                throw new OPCUAException($"Error processing value for tag '{item.DisplayName}': {ex.Message}", "OnTagValueChange", ex);
        //            }
        //        }
        //    }
        //    catch (OPCUAException)
        //    {
        //        throw;
        //    }
        //    catch (Exception ex)
        //    {
        //        throw new OPCUAException($"Unhandled error in OnTagValueChange: {ex.Message}", "OnTagValueChange", ex);
        //    }
        //}

        #endregion





        private void EnsureTagMetadata(Tag tag)
        {
            if (tag == null) throw new OPCUAException("Tag is null.", "EnsureTagMetadata");
            if (string.IsNullOrWhiteSpace(tag.NodeID))
                throw new OPCUAException("Tag.NodeID is null or empty.", "EnsureTagMetadata", tag?.DisplayName);

            // Already loaded?
            if (tag.ExpectedDataTypeId != null && tag.ExpectedValueRank != ValueRanks.Any) return;

            var node = OPCConnection.ReadNode(NodeId.Parse(tag.NodeID)) as VariableNode;
            if (node == null)
                throw new OPCUAException($"Node '{tag.NodeID}' is not a VariableNode.", "EnsureTagMetadata", tag.NodeID);

            tag.ExpectedDataTypeId = node.DataType;
            tag.ExpectedValueRank = node.ValueRank;
            if (tag.ExpectedValueRank == ValueRanks.Any) tag.ExpectedValueRank = ValueRanks.Scalar; // be strict by default
        }

        private object CoerceForWrite(object value, Tag tag)
        {
            if (value is null) return null;

            EnsureTagMetadata(tag);

            if (tag.ExpectedValueRank != ValueRanks.Scalar)
                throw new OPCUAException(
                    $"Array writes not implemented for tag '{tag.DisplayName}'.",
                    "CoerceForWrite", tag.NodeID);

            // UA metadata
            var builtIn = TypeInfo.GetBuiltInType(tag.ExpectedDataTypeId, OPCConnection.TypeTree);

            // ✅ Your SDK’s overload: (ExpandedNodeId, IEncodeableFactory)
            var sysType = TypeInfo.GetSystemType(tag.ExpectedDataTypeId, OPCConnection.MessageContext.Factory);

            // If caller already passed the right CLR type, pass through
            if (sysType != null && sysType.IsInstanceOfType(value)) return value;

            try
            {
                // Strong, lossless coercions by BuiltInType (covers int→UInt32, etc.)
                switch (builtIn)
                {
                    case BuiltInType.Boolean: return Convert.ToBoolean(value);
                    case BuiltInType.SByte: return Convert.ToSByte(value);
                    case BuiltInType.Byte: return Convert.ToByte(value);
                    case BuiltInType.Int16: return Convert.ToInt16(value);
                    case BuiltInType.UInt16: return Convert.ToUInt16(value);
                    case BuiltInType.Int32: return Convert.ToInt32(value);
                    case BuiltInType.UInt32: return Convert.ToUInt32(value);
                    case BuiltInType.Int64: return Convert.ToInt64(value);
                    case BuiltInType.UInt64: return Convert.ToUInt64(value);
                    case BuiltInType.Float: return Convert.ToSingle(value);
                    case BuiltInType.Double: return Convert.ToDouble(value);
                    case BuiltInType.String: return Convert.ToString(value);
                    case BuiltInType.DateTime: return value is DateTime dt ? dt : Convert.ToDateTime(value);
                    case BuiltInType.ByteString:
                        if (value is byte[] bytes) return bytes;
                        if (value is string b64) return Convert.FromBase64String(b64);
                        throw new InvalidCastException("Provide byte[] or Base64 string for ByteString.");
                    case BuiltInType.Guid: return value is Guid g ? g : Guid.Parse(Convert.ToString(value));
                    case BuiltInType.NodeId: return value is NodeId nid ? nid : NodeId.Parse(Convert.ToString(value));
                    case BuiltInType.ExpandedNodeId:
                        return value is ExpandedNodeId enid ? enid : ExpandedNodeId.Parse(Convert.ToString(value));
                    case BuiltInType.LocalizedText:
                        return value is LocalizedText lt ? lt : new LocalizedText(Convert.ToString(value));
                    case BuiltInType.QualifiedName:
                        return value is QualifiedName qn ? qn : QualifiedName.Parse(Convert.ToString(value));
                    case BuiltInType.ExtensionObject:
                        if (value is ExtensionObject eo) return eo;
                        throw new InvalidCastException("Provide an ExtensionObject for this tag.");
                    default:
                        // Fallback: try converting to the CLR system type, if known
                        if (sysType != null) return Convert.ChangeType(value, sysType);
                        throw new InvalidCastException($"Unhandled BuiltInType '{builtIn}'.");
                }
            }
            catch (Exception ex)
            {
                throw new OPCUAException(
                    $"Failed to coerce '{value}' ({value?.GetType().Name}) to {builtIn} for tag '{tag.DisplayName}'. {ex.Message}",
                    "CoerceForWrite", tag.NodeID, ex);
            }
        }




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

                // Coerce to server-declared type
                var coerced = CoerceForWrite(value, tag);

                var writeValue = new WriteValue
                {
                    NodeId = NodeId.Parse(tag.NodeID),
                    AttributeId = Attributes.Value,
                    Value = new DataValue(new Variant(coerced))
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

                Debug.WriteLine($"[Write] {tag.DisplayName} ({tag.NodeID}) = {coerced} ({coerced?.GetType().Name})");
            }
            catch (OPCUAException) { throw; }
            catch (ServiceResultException ex)
            {
                throw new OPCUAException($"OPC UA service error during write: {ex.Message}", "WriteNodeValue", ex);
            }
            catch (Exception ex)
            {
                throw new OPCUAException($"Unexpected error during write to node '{tag?.DisplayName}': {ex.Message}", "WriteNodeValue", ex);
            }
        }



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

                EnsureTagMetadata(tag);

                var dataValue = OPCConnection.ReadValue(NodeId.Parse(tag.NodeID));
                if (dataValue?.Value == null) return default;

                var raw = dataValue.Value;

                // If it already matches, return directly
                if (raw is T t) return t;

                var builtIn = TypeInfo.GetBuiltInType(tag.ExpectedDataTypeId, OPCConnection.TypeTree);
                var sysType = TypeInfo.GetSystemType(tag.ExpectedDataTypeId, OPCConnection.MessageContext.Factory);

                // Enums: map underlying integral value to enum
                if (typeof(T).IsEnum)
                {
                    var underlying = Enum.GetUnderlyingType(typeof(T));
                    var integral = Convert.ChangeType(raw, underlying);
                    return (T)Enum.ToObject(typeof(T), integral);
                }

                // Coerce to system type first (if different), then to T
                if (sysType != null && !sysType.IsInstanceOfType(raw))
                    raw = Convert.ChangeType(raw, sysType);

                return (T)Convert.ChangeType(raw, typeof(T));
            }
            catch (Exception ex) when (ex is InvalidCastException || ex is FormatException || ex is OverflowException)
            {
                throw new OPCUAException(
                    $"Failed to cast value of '{tag?.DisplayName}' to {typeof(T).Name}: {ex.Message}",
                    "ReadNodeValue", tag?.NodeID, ex);
            }
        }


        private void OnTagValueChange(MonitoredItem item, MonitoredItemNotificationEventArgs e)
        {
            try
            {
                if (item == null || e == null)
                    throw new OPCUAException("Invalid event arguments in OnTagValueChange.", "OnTagValueChange");

                foreach (var value in item.DequeueValues())
                {
                    var tag = TagList.FirstOrDefault(t => t.DisplayName == item.DisplayName);
                    if (tag == null)
                        throw new OPCUAException($"No matching tag found for monitored item: {item.DisplayName}", "OnTagValueChange");

                    // Preserve object + type info
                    var variant = new Variant(value.Value);
                    tag.CurrentValueObj = variant.Value;
                    tag.CurrentTypeInfo = TypeInfo.Construct(variant.Value);
                    tag.CurrentBuiltInType = tag.CurrentTypeInfo?.BuiltInType;

                    // Keep string for UI/logging if you like
                    tag.CurrentValue = variant.ToString();

                    tag.LastUpdatedTime = DateTime.Now;
                    tag.LastSourceTimeStamp = value.SourceTimestamp.ToLocalTime();
                    tag.StatusCode = value.StatusCode.ToString();

                    // Raise per-tag + global
                    tag.RaiseValueChanged();
                    TagChanged?.Invoke(this, new TagValueChangedEventArgs(tag.DisplayName, tag.CurrentValue, tag.LastUpdatedTime)
                    {
                        // If you extend your args, include object too
                        // NewValueObject = tag.CurrentValueObj
                    });
                }
            }
            catch (OPCUAException) { throw; }
            catch (Exception ex)
            {
                throw new OPCUAException($"Unhandled error in OnTagValueChange: {ex.Message}", "OnTagValueChange", ex);
            }
        }



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
                    if (string.IsNullOrWhiteSpace(tag.NodeID))
                        throw new OPCUAException("Tag.NodeID is null or empty.", "SubscribeToDataChanges", tag?.DisplayName);

                    // Prime expected UA type/value rank for later writes
                    EnsureTagMetadata(tag);

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

                OPCConnection.AddSubscription(subscription);
                subscription.Create();
                subscription.ApplyChanges();

                _subscriptions.Add(subscription);
                Debug.WriteLine($"[Subscribe] Subscription created successfully with {subscription.MonitoredItemCount} items.");
            }
            catch (OPCUAException) { throw; }
            catch (Exception ex)
            {
                throw new OPCUAException($"Unexpected error during subscription setup: {ex.Message}", "SubscribeToDataChanges", ex);
            }
        }




    }
}
