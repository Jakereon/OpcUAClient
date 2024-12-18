using System.Diagnostics;
using System.Security.Cryptography.X509Certificates;
using CommunityToolkit.Mvvm.ComponentModel;
using Opc.Ua;
using Opc.Ua.Client;
using Opc.Ua.Configuration;
using OpcUAClient;

namespace OpcUaClient
{
    /// <summary>
    /// Represents an OPC UA session with functionality for session renewal, monitoring data changes, and server communication.
    /// </summary>
    public partial class OPCSession : ObservableObject, IDisposable
    {
        #region Properities

        // Private Properties
        [ObservableProperty]
        private Settings _settings;
        private Session OPCConnection { get; set; }
        private DateTime LastTimeSessionRenewed { get; set; }
        private DateTime LastTimeOPCServerFoundAlive { get; set; }
        private CancellationTokenSource _cancellationTokenSource;
        private Task _renewalTask;
        private bool _disposed;

        // User Access Properties
        public bool InitialisationCompleted;
        public List<Tag> TagList;
        private bool _connected;

        public bool Connected
        {
            get
            {
                return OPCConnection.Connected;
            }
        }

        // Events
        public event EventHandler<string> ConnectionLost;
        public event EventHandler<TagValueChangedEventArgs> TagChanged;

        #endregion

        /// <summary>
        /// Initializes a new instance of the <see cref="OPCSession"/> class.
        /// </summary>
        public OPCSession(string serverAddress, string serverPort, List<Tag> tagList, string nameSpace)
        {
            Settings.ServerAddress = serverAddress;
            Settings.ServerPortNumber = serverPort;
            TagList = tagList;
            Settings.OPCNameSpace = nameSpace;
            LastTimeOPCServerFoundAlive = DateTime.Now;

            InitializeOPCUAClient();

            if (Settings.SessionRenewalRequired)
            {
                StartSessionRenewal();
            }
        }

        #region Security

        // Security Configuration
        public string SelectedSecurityPolicy { get; private set; }
        public MessageSecurityMode SelectedMessageSecurityMode { get; private set; }

        // User Identity
        public UserIdentity UserIdentity { get; private set; }

        // Certificate Management
        private X509Certificate2 ClientCertificate { get; set; }
        private string CertificateStorePath { get; set; } = @"%CommonApplicationData%\OPC Foundation\CertificateStores\MachineDefault";

        // Predefined Security Policies
        private static readonly string[] SecurityPolicies =
        {
            Opc.Ua.SecurityPolicies.None,
            Opc.Ua.SecurityPolicies.Basic128Rsa15,
            Opc.Ua.SecurityPolicies.Basic256,
            Opc.Ua.SecurityPolicies.Basic256Sha256
        };

        // Predefined Message Security Modes
        private static readonly MessageSecurityMode[] SecurityModes =
        {
            MessageSecurityMode.None,
            MessageSecurityMode.Sign,
            MessageSecurityMode.SignAndEncrypt
        };

        /// <summary>
        /// Configures the security policy and message security mode for the session.
        /// </summary>
        /// <param name="securityPolicy">The security policy to use.</param>
        /// <param name="securityMode">The message security mode to use.</param>
        public void ConfigureSecurity(string securityPolicy, MessageSecurityMode securityMode)
        {
            if (!SecurityPolicies.Contains(securityPolicy))
            {
                throw new ArgumentException($"Invalid security policy: {securityPolicy}");
            }

            if (!SecurityModes.Contains(securityMode))
            {
                throw new ArgumentException($"Invalid message security mode: {securityMode}");
            }

            SelectedSecurityPolicy = securityPolicy;
            SelectedMessageSecurityMode = securityMode;
        }

        /// <summary>
        /// Configures the user identity for the session.
        /// </summary>
        /// <param name="username">The username for authentication (optional).</param>
        /// <param name="password">The password for authentication (optional).</param>
        /// <param name="certificatePath">The path to the user certificate (optional).</param>
        public void ConfigureUserIdentity(string username = null, string password = null, string certificatePath = null)
        {
            if (!string.IsNullOrEmpty(username) && !string.IsNullOrEmpty(password))
            {
                // Username/Password authentication
                UserIdentity = new UserIdentity(username, password);
            }
            else if (!string.IsNullOrEmpty(certificatePath) && File.Exists(certificatePath))
            {
                // Certificate-based authentication
                var certificate = new X509Certificate2(certificatePath);
                UserIdentity = new UserIdentity(certificate);
            }
            else
            {
                // Anonymous authentication
                UserIdentity = new UserIdentity(new AnonymousIdentityToken());
            }
        }

        /// <summary>
        /// Loads an existing client certificate or creates a new one if none exists.
        /// </summary>
        /// <summary>
        /// Loads an existing client certificate or creates a new one if none exists.
        /// </summary>
        public void LoadOrCreateClientCertificate()
        {
            X509CertificateStore certificateStore = null;

            try
            {
                // Define the certificate store path
                string certificateStorePath = CertificateStorePath.Replace("%CommonApplicationData%",
                    Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData));

                certificateStore = new X509CertificateStore();
                certificateStore.Open(certificateStorePath);

                // Attempt to find an existing certificate
                //ClientCertificate = FindExistingCertificate(certificateStore);

                // If no certificate exists, create one
                if (ClientCertificate == null)
                {
                    Console.WriteLine("No client certificate found. Creating a new certificate...");
                    //ClientCertificate = CreateNewCertificate();
                    certificateStore.Add(ClientCertificate);
                }

                Console.WriteLine("Client certificate loaded successfully.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error loading or creating client certificate: {ex.Message}");
                throw;
            }
            finally
            {
                // Properly close the certificate store
                certificateStore?.Close();
            }
        }

        /// <summary>
        /// Finds an existing certificate in the store.
        /// </summary>
        private async Task<X509Certificate2> FindExistingCertificateAsync(X509CertificateStore certificateStore)
        {
            var certificates = await certificateStore.Enumerate(); // Await the async task

            foreach (var cert in certificates)
            {
                if (cert.Subject.Contains("CN=OPC UA Client") && cert.NotAfter > DateTime.UtcNow)
                {
                    return cert;
                }
            }

            return null;
        }

        /// <summary>
        /// Initializes the OPC UA session with configured security settings.
        /// </summary>
        //public void InitializeOPCUAClient()
        //{
        //    var config = CreateApplicationConfiguration();

        //    var endpointDescription = CoreClientUtils.SelectEndpoint(
        //        $"opc.tcp://{Settings.ServerAddress}:{Settings.ServerPortNumber}",
        //        SelectedSecurityPolicy != SecurityPolicies.None);

        //    var endpoint = new ConfiguredEndpoint(null, endpointDescription, EndpointConfiguration.Create(config))
        //    {
        //        SecurityPolicyUri = SelectedSecurityPolicy,
        //        SecurityMode = SelectedMessageSecurityMode
        //    };

        //    OPCConnection = Session.Create(
        //        config,
        //        endpoint,
        //        false,
        //        false,
        //        "MySession",
        //        60000,
        //        UserIdentity,
        //        null).GetAwaiter().GetResult();
        //}

        /// <summary>
        /// Displays available security policies and modes.
        /// </summary>
        public void DisplayAvailableSecurityOptions()
        {
            Console.WriteLine("Available Security Policies:");
            foreach (var policy in SecurityPolicies)
            {
                Console.WriteLine($"- {policy}");
            }

            Console.WriteLine("\nAvailable Message Security Modes:");
            foreach (var mode in SecurityModes)
            {
                Console.WriteLine($"- {mode}");
            }
        }



        #endregion

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
                    Debug.WriteLine($"Attempt {attempt} failed: {ex.Message}");
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
        /// Initializes the OPC UA client and establishes a session.
        /// </summary>
        public void InitializeOPCUAClient()
        {
            var config = CreateApplicationConfiguration();

            var application = new ApplicationInstance
            {
                ApplicationName = Settings.MyApplicationName,
                ApplicationType = ApplicationType.Client,
                ApplicationConfiguration = config
            };

            application.CheckApplicationInstanceCertificate(false, 2048).GetAwaiter().GetResult();

            var selectedEndpoint = CoreClientUtils.SelectEndpoint(
                $"opc.tcp://{Settings.ServerAddress}:{Settings.ServerPortNumber}",
                useSecurity: Settings.SecurityEnabled);

            OPCConnection = Session.Create(
                config,
                new ConfiguredEndpoint(null, selectedEndpoint, EndpointConfiguration.Create(config)),
                false, "", 60000, null, null).GetAwaiter().GetResult();

            InitializeKeepAliveMonitoring();
            SubscribeToDataChanges();
        }

        /// <summary>
        /// Creates the OPC UA client application configuration.
        /// </summary>
        private ApplicationConfiguration CreateApplicationConfiguration()
        {
            var config = new ApplicationConfiguration
            {
                ApplicationName = Settings.MyApplicationName,
                ApplicationUri = Utils.Format(@"urn:{0}:" + Settings.MyApplicationName, Settings.ServerAddress),
                ApplicationType = ApplicationType.Client,
                SecurityConfiguration = new SecurityConfiguration
                {
                    ApplicationCertificate = new CertificateIdentifier
                    {
                        StoreType = "Directory",
                        StorePath = @"%CommonApplicationData%\OPC Foundation\CertificateStores\MachineDefault",
                        SubjectName = Utils.Format(@"CN={0}, DC={1}", Settings.MyApplicationName, Settings.ServerAddress)
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
                TraceConfiguration = new Opc.Ua.TraceConfiguration()
            };

            config.Validate(ApplicationType.Client).GetAwaiter().GetResult();

            if (config.SecurityConfiguration.AutoAcceptUntrustedCertificates)
            {
                config.CertificateValidator.CertificateValidation += (sender, e) =>
                {
                    e.Accept = (e.Error.StatusCode == StatusCodes.BadCertificateUntrusted);
                };
            }

            return config;
        }

        /// <summary>
        /// Starts the session renewal process in a background task.
        /// </summary>
        private void StartSessionRenewal()
        {
            _cancellationTokenSource = new CancellationTokenSource();
            _renewalTask = Task.Run(() => RenewSessionAsync(_cancellationTokenSource.Token));
        }

        /// <summary>
        /// Checks if the OPC server is alive by performing a lightweight read operation.
        /// </summary>
        public bool IsServerAlive()
        {
            try
            {
                if (OPCConnection != null && OPCConnection.Connected)
                {
                    var nodeId = new NodeId("i=2258"); // Server Current Time node
                    var dataValue = OPCConnection.ReadValue(nodeId);
                    return dataValue.StatusCode == StatusCodes.Good;
                }
                return false;
            }
            catch
            {
                return false;
            }
        }

        /// <summary>
        /// Periodically renews the OPC session if it becomes stale or the server is unresponsive.
        /// </summary>
        private async Task RenewSessionAsync(CancellationToken token)
        {
            while (!token.IsCancellationRequested)
            {
                try
                {
                    if ((DateTime.Now - LastTimeSessionRenewed).TotalMinutes > Settings.SessionRenewalPeriodMins
                        || (DateTime.Now - LastTimeOPCServerFoundAlive).TotalSeconds > 60)
                    {
                        OPCConnection?.Close();
                        OPCConnection?.Dispose();

                        InitializeOPCUAClient();
                        LastTimeSessionRenewed = DateTime.Now;
                    }
                }
                catch
                {
                    // Handle session renewal exceptions silently
                }

                await Task.Delay(2000, token); // Wait 2 seconds before next check
            }
        }

        /// <summary>
        /// Initializes KeepAlive monitoring to track the health of the OPC UA connection.
        /// </summary>
        private void InitializeKeepAliveMonitoring()
        {
            if (OPCConnection == null)
            {
                throw new InvalidOperationException("OPC connection is not initialized.");
            }

            // Subscribe to the KeepAlive event of the OPC session
            OPCConnection.KeepAlive += (sender, e) =>
            {
                if (!ServiceResult.IsGood(e.Status))
                {
                    // Connection is lost or in a bad state
                    Debug.WriteLine($"KeepAlive Error: {e.Status}");

                    // Attempt to handle the connection loss
                    HandleConnectionLoss();
                }
                else
                {
                    // Connection is alive; update the last successful check time
                    LastTimeOPCServerFoundAlive = DateTime.Now;
                    Debug.WriteLine($"KeepAlive Successful at {LastTimeOPCServerFoundAlive}");
                }
            };

            Debug.WriteLine("KeepAlive monitoring initialized.");
        }
        private void HandleConnectionLoss()
        {
            try
            {
                Debug.WriteLine("Attempting to reconnect...");
                OPCConnection?.Close();
                OPCConnection?.Dispose();

                InitializeOPCUAClient(); // Reinitialize the session
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Reconnection failed: {ex.Message}");
            }
        }

        /// <summary>
        /// Disposes of resources used by the OPCSession class.
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Actual implementation of Dispose to release managed and unmanaged resources.
        /// </summary>
        /// <param name="disposing">True if disposing managed resources; otherwise, false.</param>
        protected virtual void Dispose(bool disposing)
        {
            if (_disposed) return;

            if (disposing)
            {
                // Dispose managed resources here
                if (OPCConnection != null)
                {
                    try
                    {
                        OPCConnection.Close();
                        OPCConnection.Dispose();
                    }
                    catch (Exception ex)
                    {
                        Debug.WriteLine($"Error while disposing OPCConnection: {ex.Message}");
                    }
                }

                _cancellationTokenSource?.Cancel();
                _cancellationTokenSource?.Dispose();
            }

            // Release unmanaged resources here if any

            _disposed = true;
        }

        /// <summary>
        /// Finalizer for OPCSession class to ensure unmanaged resources are released.
        /// </summary>
        ~OPCSession()
        {
            Dispose(false);
        }

        #endregion

        #region Server Method Calls

        /// <summary>
        /// Invokes a method on the OPC UA server.
        /// </summary>
        /// <param name="objectNodeId">The NodeId of the object owning the method.</param>
        /// <param name="methodNodeId">The NodeId of the method to invoke.</param>
        /// <param name="inputArguments">An array of input arguments for the method.</param>
        /// <returns>An array of output arguments from the method.</returns>
        /// <summary>
        /// Invokes a method on the OPC UA server.
        /// </summary>
        /// <param name="objectNodeId">The NodeId of the object owning the method.</param>
        /// <param name="methodNodeId">The NodeId of the method to invoke.</param>
        /// <param name="inputArguments">An array of input arguments for the method.</param>
        /// <returns>An array of Variants representing the output arguments.</returns>
        public Variant[] InvokeServerMethod(NodeId objectNodeId, NodeId methodNodeId, Variant[] inputArguments)
        {
            if (OPCConnection == null || !OPCConnection.Connected)
            {
                throw new InvalidOperationException("OPC connection is not established.");
            }

            try
            {
                // Call the method and retrieve the output arguments
                var outputArguments = OPCConnection.Call(objectNodeId, methodNodeId, inputArguments);

                // Convert the IList<object> to Variant[]
                return outputArguments?.Select(o => new Variant(o)).ToArray() ?? Array.Empty<Variant>();
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Error invoking method on server: {ex.Message}");
                throw;
            }
        }



        #endregion

        #region Server Events

        /// <summary>
        /// Monitors server-generated events and raises an event when an event is received.
        /// </summary>
        /// <param name="startNodeId">The NodeId to start monitoring events from.</param>
        public void MonitorServerEvents(NodeId startNodeId)
        {
            if (OPCConnection == null || !OPCConnection.Connected)
            {
                throw new InvalidOperationException("OPC connection is not established.");
            }

            try
            {
                var subscription = new Opc.Ua.Client.Subscription(OPCConnection.DefaultSubscription)
                {
                    DisplayName = "Event Subscription",
                    PublishingInterval = 1000,
                    PublishingEnabled = true
                };

                OPCConnection.AddSubscription(subscription);
                subscription.Create();

                var eventFilter = new EventFilter
                {
                    SelectClauses = new SimpleAttributeOperandCollection
            {
                new SimpleAttributeOperand
                {
                    TypeDefinitionId = ObjectTypeIds.BaseEventType,
                    AttributeId = Attributes.Value,
                    BrowsePath = new QualifiedNameCollection { new QualifiedName("Message") }
                }
            }
                };

                var monitoredItem = new Opc.Ua.Client.MonitoredItem(subscription.DefaultItem)
                {
                    StartNodeId = startNodeId,
                    AttributeId = Attributes.EventNotifier,
                    MonitoringMode = MonitoringMode.Reporting,
                    Filter = eventFilter
                };

                monitoredItem.Notification += (sender, e) =>
                {
                    foreach (var notification in e.NotificationValue as EventFieldListCollection)
                    {
                        EventReceived?.Invoke(this, new EventReceivedEventArgs(notification.EventFields));
                    }
                };

                subscription.AddItem(monitoredItem);
                subscription.ApplyChanges();
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Error monitoring server events: {ex.Message}");
            }
        }

        /// <summary>
        /// Event raised when a server event is received.
        /// </summary>
        public event EventHandler<EventReceivedEventArgs> EventReceived;

        /// <summary>
        /// Arguments for the EventReceived event.
        /// </summary>
        public class EventReceivedEventArgs : EventArgs
        {
            public IList<Variant> EventFields { get; }

            public EventReceivedEventArgs(IList<Variant> eventFields)
            {
                EventFields = eventFields;
            }
        }


        #endregion

        #region ServerQueries

        /// <summary>
        /// Explores the namespace of the OPC UA server.
        /// </summary>
        /// <returns>A list of available nodes in the server's namespace.</returns>
        /// <summary>
        /// Explores the namespace of the OPC UA server.
        /// </summary>
        public List<NodeId> BrowseNamespace()
        {
            var browser = new Browser(OPCConnection)
            {
                BrowseDirection = BrowseDirection.Forward,
                NodeClassMask = (int)(uint)NodeClass.Variable,
                IncludeSubtypes = true,
                ReferenceTypeId = ReferenceTypeIds.HierarchicalReferences
            };

            // Browse the Objects folder and get the nodes
            var nodes = browser.Browse(Objects.ObjectsFolder);

            // Convert ExpandedNodeId to NodeId
            return nodes
                .Select(n => ExpandedNodeId.ToNodeId(n.NodeId, OPCConnection.NamespaceUris))
                .Where(nodeId => nodeId != null) // Filter out null results
                .ToList();
        }


        /// <summary>
        /// Discovers available OPC UA servers on the network with optional filters.
        /// </summary>
        public async Task<List<EndpointDescription>> DiscoverServersAsync(
            string discoveryUrl = "opc.tcp://localhost:4840",
            string securityPolicyFilter = null,
            ApplicationType? applicationTypeFilter = null)
        {
            try
            {
                // Wrap the discovery URL in a StringCollection
                var discoveryUrls = new StringCollection { discoveryUrl };

                // Create a DiscoveryClient instance
                var discoveryClient = DiscoveryClient.Create(ConvertToUri(discoveryUrl));

                // Use DiscoveryClient to find endpoints
                var endpoints = await discoveryClient.GetEndpointsAsync(discoveryUrls, CancellationToken.None);

                // Apply filters if specified
                var filteredEndpoints = endpoints
                    .Where(endpoint =>
                        (string.IsNullOrEmpty(securityPolicyFilter) || endpoint.SecurityPolicyUri == securityPolicyFilter) &&
                        (!applicationTypeFilter.HasValue || endpoint.Server.ApplicationType == applicationTypeFilter))
                    .ToList();

                return filteredEndpoints;
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Error discovering servers: {ex.Message}");
                return new List<EndpointDescription>();
            }
        }


        public Uri ConvertToUri(string uriString)
        {
            if (string.IsNullOrWhiteSpace(uriString))
            {
                throw new ArgumentException("The provided URI string is null or empty.", nameof(uriString));
            }

            // Try to create the URI
            if (Uri.TryCreate(uriString, UriKind.Absolute, out Uri result))
            {
                return result;
            }
            else
            {
                throw new UriFormatException($"Invalid URI format: {uriString}");
            }
        }


        #endregion

        #region TagHandling

        /// <summary>
        /// Adds a new tag to the session.
        /// </summary>
        /// <param name="tag">The tag to add.</param>
        public void AddTag(Tag tag)
        {
            if (!TagList.Contains(tag))
            {
                TagList.Add(tag);
                SubscribeToDataChanges(); // Re-subscribe to include the new tag
            }
        }

        /// <summary>
        /// Removes a tag from the session.
        /// </summary>
        /// <param name="tag">The tag to remove.</param>
        public void RemoveTag(Tag tag)
        {
            if (TagList.Contains(tag))
            {
                TagList.Remove(tag);
                SubscribeToDataChanges(); // Re-subscribe to update the monitored items
            }
        }

        #endregion

        #region Subcribe / Read

        /// <summary>
        /// Subscribes to data changes on the OPC server for all tags in the TagList.
        /// </summary>
        public void SubscribeToDataChanges()
        {
            if (OPCConnection == null || !OPCConnection.Connected)
            {
                return;
            }

            try
            {
                var subscription = new Opc.Ua.Client.Subscription(OPCConnection.DefaultSubscription)
                {
                    DisplayName = "Console ReferenceClient Subscription",
                    PublishingEnabled = true,
                    PublishingInterval = 1000
                };

                OPCConnection.AddSubscription(subscription);
                subscription.Create();

                foreach (var tag in TagList)
                {
                    var monitoredItem = new Opc.Ua.Client.MonitoredItem(subscription.DefaultItem)
                    {
                        StartNodeId = tag.NodeID,
                        AttributeId = Attributes.Value,
                        DisplayName = tag.DisplayName,
                        SamplingInterval = 1000
                    };

                    monitoredItem.Notification += OnTagValueChange;
                    subscription.AddItem(monitoredItem);
                }
                subscription.ApplyChanges();
            }
            catch
            {
                // Handle subscription creation errors
            }
        }

        /// <summary>
        /// Handles tag value changes and raises the TagChanged event.
        /// </summary>
        private void OnTagValueChange(Opc.Ua.Client.MonitoredItem item, MonitoredItemNotificationEventArgs e)
        {
            foreach (var value in item.DequeueValues())
            {
                var tag = TagList.FirstOrDefault(t => t.DisplayName == item.DisplayName);
                if (tag != null)
                {
                    tag.CurrentValue = value.Value?.ToString();
                    tag.LastUpdatedTime = DateTime.Now;
                    tag.LastSourceTimeStamp = value.SourceTimestamp.ToLocalTime();
                    tag.StatusCode = value.StatusCode.ToString();

                    TagChanged?.Invoke(this, new TagValueChangedEventArgs(tag.DisplayName, tag.CurrentValue, tag.LastUpdatedTime));
                }
            }
        }

        /// <summary>
        /// Reads the value of a specific tag from the OPC server.
        /// </summary>
        public T ReadNodeValue<T>(Tag tag)
        {
            try
            {
                var nodeId = new NodeId(tag.NodeID);
                var dataValue = OPCConnection.ReadValue(nodeId);

                if (dataValue?.Value == null)
                {
                    throw new InvalidOperationException($"Node {tag.DisplayName} returned a null value.");
                }

                return (T)Convert.ChangeType(dataValue.Value, typeof(T));
            }
            catch
            {
                throw;
            }
        }

        /// <summary>
        /// Subscribes only to tags that match the given filter predicate.
        /// </summary>
        /// <param name="filter">A predicate to filter tags for subscription.</param>
        public void SubscribeToFilteredTags(Func<Tag, bool> filter)
        {
            if (OPCConnection == null || !OPCConnection.Connected)
            {
                return;
            }

            try
            {
                var subscription = new Opc.Ua.Client.Subscription(OPCConnection.DefaultSubscription)
                {
                    DisplayName = "Filtered Subscription",
                    PublishingEnabled = true,
                    PublishingInterval = 1000
                };

                OPCConnection.AddSubscription(subscription);
                subscription.Create();

                foreach (var tag in TagList.Where(filter))
                {
                    var monitoredItem = new Opc.Ua.Client.MonitoredItem(subscription.DefaultItem)
                    {
                        StartNodeId = tag.NodeID,
                        AttributeId = Attributes.Value,
                        DisplayName = tag.DisplayName,
                        SamplingInterval = 1000
                    };

                    monitoredItem.Notification += OnTagValueChange;
                    subscription.AddItem(monitoredItem);
                }
                subscription.ApplyChanges();
            }
            catch
            {
                // Handle subscription creation errors
            }
        }


        /// <summary>
        /// Reads historical data for a specific tag.
        /// </summary>
        public List<DataValue> ReadHistoricalData(Tag tag, DateTime startTime, DateTime endTime)
        {
            if (OPCConnection == null || !OPCConnection.Connected)
            {
                throw new InvalidOperationException("OPC connection is not established.");
            }

            // Define the history read details
            var historyReadDetails = new ReadRawModifiedDetails
            {
                IsReadModified = false,
                StartTime = startTime,
                EndTime = endTime,
                NumValuesPerNode = 0, // Unlimited
                ReturnBounds = true
            };

            // Wrap the historyReadDetails in an ExtensionObject
            ExtensionObject extensionObject = new ExtensionObject(historyReadDetails);

            // Define the nodes to read
            var nodesToRead = new HistoryReadValueIdCollection
    {
        new HistoryReadValueId
        {
            NodeId = new NodeId(tag.NodeID),
            IndexRange = null,
            DataEncoding = null
        }
    };

            // Perform the history read
            OPCConnection.HistoryRead(
                requestHeader: null,
                historyReadDetails: extensionObject, // Correct parameter name
                timestampsToReturn: TimestampsToReturn.Both,
                releaseContinuationPoints: false,
                nodesToRead: nodesToRead,
                results: out HistoryReadResultCollection results,
                diagnosticInfos: out DiagnosticInfoCollection diagnosticInfos
            );

            // Extract and decode the historical data
            var historicalData = new List<DataValue>();

            if (results != null && results.Count > 0 && results[0].HistoryData != null)
            {
                var historyData = results[0].HistoryData as ExtensionObject;

                if (historyData != null)
                {
                    // Decode the ExtensionObject into DataValueCollection
                    var decodedData = historyData.Body as DataValueCollection;

                    if (decodedData != null)
                    {
                        historicalData.AddRange(decodedData);
                    }
                }
            }

            return historicalData;
        }



        #endregion

        #region Write

        /// <summary>
        /// Writes a value to a specific tag on the OPC server.
        /// </summary>
        /// <param name="tag">The tag to which the value will be written.</param>
        /// <param name="value">The value to write.</param>
        /// <returns>True if the write operation succeeds; otherwise, false.</returns>
        public void WriteNodeValue(Tag tag, object value)
        {
            //Check if connected

            try
            {
                var writeValue = new WriteValue
                {
                    NodeId = new NodeId(tag.NodeID),
                    AttributeId = Attributes.Value,
                    Value = new DataValue
                    {
                        Value = value,
                        StatusCode = StatusCodes.Good,
                        ServerTimestamp = DateTime.UtcNow,
                        SourceTimestamp = DateTime.UtcNow
                    }
                };

                // Prepare a WriteValueCollection for the operation
                var writeCollection = new WriteValueCollection { writeValue };

                // Perform the write operation
                OPCConnection.Write(null, writeCollection, out StatusCodeCollection results, out DiagnosticInfoCollection diagnosticInfos);

                // Check the results
                if (results[0] != StatusCodes.Good)
                {
                    throw new OPCUAException("Failed to write to node.", "Write", tag.NodeID); ;
                }
            }
            catch (Exception ex)
            {
                throw new OPCUAException("Failed to write to node.", "Write", tag.NodeID); ;
            }
        }

        /// <summary>
        /// Writes multiple values to the specified tags in a batch.
        /// </summary>
        /// <param name="tagValues">A dictionary of tags and their corresponding values.</param>
        /// <returns>A list of status codes indicating the result of each write operation.</returns>
        public List<StatusCode> WriteNodeValues(Dictionary<Tag, object> tagValues)
        {
            if (OPCConnection == null || !OPCConnection.Connected)
            {
                throw new InvalidOperationException("OPC connection is not established.");
            }

            var writeCollection = new WriteValueCollection();

            foreach (var entry in tagValues)
            {
                writeCollection.Add(new WriteValue
                {
                    NodeId = new NodeId(entry.Key.NodeID),
                    AttributeId = Attributes.Value,
                    Value = new DataValue
                    {
                        Value = entry.Value,
                        StatusCode = StatusCodes.Good,
                        ServerTimestamp = DateTime.UtcNow,
                        SourceTimestamp = DateTime.UtcNow
                    }
                });
            }

            OPCConnection.Write(null, writeCollection, out StatusCodeCollection results, out DiagnosticInfoCollection diagnosticInfos);

            return results.ToList();
        }

        #endregion

        #region Server Diagnostics
        /// <summary>
        /// Retrieves the server diagnostics summary.
        /// </summary>
        public string GetServerDiagnosticsSummary()
        {
            if (OPCConnection == null || !OPCConnection.Connected)
            {
                throw new InvalidOperationException("OPC connection is not established.");
            }

            try
            {
                // Use the manual NodeId for ServerDiagnosticsSummary
                var serverDiagnosticsNodeId = new NodeId(2256, 0); // Identifier = 2256, NamespaceIndex = 0

                // Read the value of the diagnostics summary node
                var diagnostics = OPCConnection.ReadValue(serverDiagnosticsNodeId);

                // Safely return the result as a string
                return diagnostics?.Value?.ToString();
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Error retrieving server diagnostics summary: {ex.Message}");
                return null;
            }
        }

        /// <summary>
        /// Retrieves a specific diagnostic counter from the server.
        /// </summary>
        /// <param name="nodeId">The NodeId of the diagnostic counter to retrieve.</param>
        /// <returns>The value of the diagnostic counter, or null if unavailable.</returns>
        public object GetDiagnosticCounter(NodeId nodeId)
        {
            if (OPCConnection == null || !OPCConnection.Connected)
            {
                throw new InvalidOperationException("OPC connection is not established.");
            }

            try
            {
                var counterValue = OPCConnection.ReadValue(nodeId);
                return counterValue.Value;
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Error retrieving diagnostic counter: {ex.Message}");
                return null;
            }
        }

        /// <summary>
        /// Retrieves the list of active sessions on the server.
        /// </summary>
        /// <returns>A list of session diagnostics, or an empty list if unavailable.</returns>
        public List<string> GetActiveSessions()
        {
            if (OPCConnection == null || !OPCConnection.Connected)
            {
                throw new InvalidOperationException("OPC connection is not established.");
            }

            try
            {
                // NodeId for SessionsDiagnosticsSummary (manual NodeId: 2270 in Namespace 0)
                var sessionsDiagnosticsNodeId = new NodeId(2270, 0);

                // Read the value of the SessionsDiagnosticsSummary node
                var sessions = OPCConnection.ReadValue(sessionsDiagnosticsNodeId);

                // Ensure the response contains ExtensionObject[]
                if (sessions?.Value is ExtensionObject[] sessionExtensions)
                {
                    var activeSessions = new List<string>();

                    foreach (var extension in sessionExtensions)
                    {
                        // Decode the ExtensionObject into its SessionDiagnosticsDataType
                        var sessionData = extension.Body as SessionDiagnosticsDataType;

                        if (sessionData != null)
                        {
                            activeSessions.Add($"SessionId: {sessionData.SessionId}, Name: {sessionData.SessionName}");
                        }
                    }

                    return activeSessions;
                }

                return new List<string>();
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Error retrieving active sessions: {ex.Message}");
                return new List<string>();
            }
        }

        #endregion

        #region Monitoring

        /// <summary>
        /// Monitors a condition node for alarms and raises an event when the alarm status changes.
        /// </summary>
        /// <param name="nodeId">The NodeId of the condition node to monitor.</param>
        public void MonitorAlarm(NodeId nodeId)
        {
            if (OPCConnection == null || !OPCConnection.Connected)
            {
                throw new InvalidOperationException("OPC connection is not established.");
            }

            try
            {
                var subscription = new Opc.Ua.Client.Subscription(OPCConnection.DefaultSubscription)
                {
                    DisplayName = "Alarm Subscription",
                    PublishingEnabled = true,
                    PublishingInterval = 1000
                };

                OPCConnection.AddSubscription(subscription);
                subscription.Create();

                var monitoredItem = new Opc.Ua.Client.MonitoredItem(subscription.DefaultItem)
                {
                    StartNodeId = nodeId,
                    AttributeId = Attributes.Value,
                    DisplayName = "AlarmCondition",
                    MonitoringMode = MonitoringMode.Reporting,
                    SamplingInterval = 1000
                };

                monitoredItem.Notification += (sender, e) =>
                {
                    foreach (var notification in e.NotificationValue as MonitoredItemNotificationCollection)
                    {
                        var alarmState = notification.Value.WrappedValue.Value;
                        Console.WriteLine($"Alarm state changed: {alarmState}");
                        AlarmStateChanged?.Invoke(this, new AlarmEventArgs(nodeId, alarmState));
                    }
                };

                subscription.AddItem(monitoredItem);
                subscription.ApplyChanges();
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Error monitoring alarm: {ex.Message}");
            }
        }

        /// <summary>
        /// Event raised when an alarm state changes.
        /// </summary>
        public event EventHandler<AlarmEventArgs> AlarmStateChanged;



        /// <summary>
        /// Acknowledges an alarm condition on the server.
        /// </summary>
        /// <param name="nodeId">The NodeId of the condition to acknowledge.</param>
        /// <param name="comment">The comment to include with the acknowledgment.</param>
        /// <returns>True if the acknowledgment was successful; otherwise, false.</returns>
        public bool AcknowledgeAlarm(NodeId nodeId, string comment = "Acknowledged")
        {
            if (OPCConnection == null || !OPCConnection.Connected)
            {
                throw new InvalidOperationException("OPC connection is not established.");
            }

            try
            {
                // NodeId for the Acknowledge method on the condition node
                var acknowledgeMethodNodeId = new NodeId($"{nodeId.Identifier}/Acknowledge");

                // Input arguments for the Acknowledge method: EventId and Comment
                var eventIdVariant = new Variant(new byte[0]); // Empty EventId
                var commentVariant = new Variant(new LocalizedText(comment));

                var inputArguments = new Variant[] { eventIdVariant, commentVariant };

                // Call the Acknowledge method on the server
                var outputArguments = OPCConnection.Call(nodeId, acknowledgeMethodNodeId, inputArguments);

                Console.WriteLine("Alarm acknowledged successfully.");
                return true;
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Error acknowledging alarm: {ex.Message}");
                return false;
            }
        }


        /// <summary>
        /// Retrieves all active alarms or conditions from a specified node.
        /// </summary>
        /// <param name="nodeId">The NodeId to query for active alarms.</param>
        /// <returns>A list of active alarms.</returns>
        public List<string> GetActiveAlarms(NodeId nodeId)
        {
            if (OPCConnection == null || !OPCConnection.Connected)
            {
                throw new InvalidOperationException("OPC connection is not established.");
            }

            try
            {
                var activeAlarms = new List<string>();

                var events = OPCConnection.ReadValue(nodeId);
                if (events.Value is ExtensionObject[] conditions)
                {
                    foreach (var condition in conditions)
                    {
                        var alarm = condition.Body.ToString();
                        activeAlarms.Add(alarm);
                    }
                }

                return activeAlarms;
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Error retrieving active alarms: {ex.Message}");
                return new List<string>();
            }
        }

        #endregion

        //#region ToTest

        ///// <summary>
        ///// Reads the value of a tag asynchronously.
        ///// </summary>
        ///// <param name="tag">The tag to read.</param>
        ///// <returns>The value of the tag.</returns>
        //public async Task<object> ReadNodeValueAsync(Tag tag)
        //{
        //    if (OPCConnection == null || !OPCConnection.Connected)
        //    {
        //        throw new InvalidOperationException("OPC connection is not established.");
        //    }

        //    var nodeId = new NodeId(tag.NodeID);
        //    var dataValue = await Task.Run(() => OPCConnection.ReadValue(nodeId));
        //    return dataValue?.Value;
        //}

        ///// <summary>
        ///// Writes a value to a tag asynchronously.
        ///// </summary>
        ///// <param name="tag">The tag to write to.</param>
        ///// <param name="value">The value to write.</param>
        ///// <returns>True if the operation succeeds, otherwise false.</returns>
        //public async Task<bool> WriteNodeValueAsync(Tag tag, object value)
        //{
        //    if (OPCConnection == null || !OPCConnection.Connected)
        //    {
        //        throw new InvalidOperationException("OPC connection is not established.");
        //    }

        //    var writeValue = new WriteValue
        //    {
        //        NodeId = new NodeId(tag.NodeID),
        //        AttributeId = Attributes.Value,
        //        Value = new DataValue
        //        {
        //            Value = value,
        //            StatusCode = StatusCodes.Good,
        //            ServerTimestamp = DateTime.UtcNow,
        //            SourceTimestamp = DateTime.UtcNow
        //        }
        //    };

        //    var writeCollection = new WriteValueCollection { writeValue };
        //    var results = await Task.Run(() =>
        //    {
        //        OPCConnection.Write(null, writeCollection, out StatusCodeCollection statusCodes, out DiagnosticInfoCollection _);
        //        return statusCodes;
        //    });

        //    return results[0] == StatusCodes.Good;
        //}

        ///// <summary>
        ///// Retrieves a list of supported security policies from the server.
        ///// </summary>
        ///// <returns>A list of supported security policies.</returns>
        //public List<string> GetSupportedSecurityPolicies()
        //{
        //    if (OPCConnection == null)
        //    {
        //        throw new InvalidOperationException("OPC connection is not established.");
        //    }

        //    return OPCConnection.EndpointDescription.Server.ApplicationDescription.ServerCapabilities
        //        .SupportedSecurityPolicies
        //        .Select(policy => policy.Uri.ToString())
        //        .ToList();
        //}

        ///// <summary>
        ///// Retrieves the list of namespaces supported by the server.
        ///// </summary>
        ///// <returns>A list of namespaces.</returns>
        //public List<string> GetNamespaces()
        //{
        //    if (OPCConnection == null)
        //    {
        //        throw new InvalidOperationException("OPC connection is not established.");
        //    }

        //    return OPCConnection.NamespaceUris.ToArray().ToList();
        //}


        ///// <summary>
        ///// Adjusts the sampling rate for a specific tag.
        ///// </summary>
        ///// <param name="tag">The tag to adjust.</param>
        ///// <param name="newRate">The new sampling rate in milliseconds.</param>
        //public void AdjustSamplingRate(Tag tag, int newRate)
        //{
        //    var monitoredItem = OPCConnection.DefaultSubscription?.MonitoredItems
        //        .FirstOrDefault(item => item.StartNodeId == tag.NodeID);

        //    if (monitoredItem != null)
        //    {
        //        monitoredItem.SamplingInterval = newRate;
        //        OPCConnection.DefaultSubscription.ApplyChanges();
        //    }
        //}


        //#endregion
    }
}
