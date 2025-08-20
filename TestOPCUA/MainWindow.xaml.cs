using System.Diagnostics;
using System.Windows;
using OpcUaClient;
using OpcUAClient;

namespace TestOPCUA
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            Debug.WriteLine("MainWindow constructor called.");
            InitializeComponent();
        }

        OPCSession opcSession;

        //public static Tag RequestType => new Tag("RequestType", "ns=2;s=RequestType");
        public static Tag RequestType => new Tag("RequestType", "ns=2;s=CEL_FBC_COUNTER_01.Controller.RequestType");

        private void Button_Click(object sender, RoutedEventArgs e)
        {
            Debug.WriteLine("Connect button clicked.");

            // Create settings for OPC UA connection
            //var settings = new Settings
            //{
            //    MyApplicationName = "MyOPCClient",
            //    ServerAddress = "broomco-90yvst3",
            //    ServerPort = "62640",
            //    SecurityEnabled = false,
            //    SessionRenewalRequired = true
            //};
            var settings = new Settings
            {
                ServerAddress = "broomcoKWDEV01.hdna.hd.lan",
                ServerPort = "49320",
                ServerPath = "broomcoKWDEV01",
                MyApplicationName = "MyOpcUaClient",
                SecurityEnabled = false,
                SessionRenewalRequired = true
            };

            Debug.WriteLine("Creating new OPCSession instance.");
            opcSession = new OPCSession(settings);

            // --- 1. Add tags to TagList ---
            // Example: create and add a few tags
            var fabricColorTag = new Tag("FabricColor", "ns=2;s=CEL_FBC_COUNTER_01.Controller.FabricColor");
            var messageTag = new Tag("Message", "ns=2;s=CEL_FBC_COUNTER_01.Controller.Message");
            var remainingCellCountTag = new Tag("RemainingCellCount", "ns=2;s=CEL_FBC_COUNTER_01.Controller.RemainingCellCount");
            var requestTypeTag = new Tag("RequestType", "ns=2;s=CEL_FBC_COUNTER_01.Controller.RequestType");
            var statusTag = new Tag("Status", "ns=2;s=CEL_FBC_COUNTER_01.Controller.Status");
            var totalCellCountTag = new Tag("TotalCellCount", "ns=2;s=CEL_FBC_COUNTER_01.Controller.TotalCellCount");
            var unitCellCountTag = new Tag("UnitCellCount", "ns=2;s=CEL_FBC_COUNTER_01.Controller.UnitCellCount");

            // Add them all to your session's tag list
            opcSession.TagList.Add(fabricColorTag);
            opcSession.TagList.Add(messageTag);
            opcSession.TagList.Add(remainingCellCountTag);
            opcSession.TagList.Add(requestTypeTag);
            opcSession.TagList.Add(statusTag);
            opcSession.TagList.Add(totalCellCountTag);
            opcSession.TagList.Add(unitCellCountTag);

            Debug.WriteLine("Tags added to TagList.");

            Debug.WriteLine("Calling InitializeOPCUAClient...");
            opcSession.InitializeOPCUAClient();

            if (!opcSession.Connected)
            {
                Debug.WriteLine("Failed to connect to OPC UA server.");
                Console.WriteLine("Failed to connect to the OPC UA server.");
                return;
            }

            Debug.WriteLine("Connected successfully to OPC UA server.");
            Console.WriteLine("Connected successfully!");

            // --- 2. Subscribe to data changes for all tags ---
            opcSession.SubscribeToDataChanges();

            // --- 3. Attach event handler to the "status" tag ---
            statusTag.ValueChanged += tag =>
            {
                // Show a message box popup when the status tag changes
                Application.Current.Dispatcher.Invoke(() =>
                {
                    MessageBox.Show($"Status tag changed! New value: {tag.CurrentValue}", "Status Changed", MessageBoxButton.OK, MessageBoxImage.Information);
                });
            };

            // (Optional) You can add per-tag logic for other tags as well
            statusTag.ValueChanged += tag =>
            {
                Debug.WriteLine($"Temperature tag changed: {tag.CurrentValue}");
                // Additional logic for temperature changes...
            };
        }


       private void Button_Click_1(object sender, RoutedEventArgs e)
        {
            Debug.WriteLine("Read button clicked.");

            if (opcSession == null || !opcSession.Connected)
            {
                Debug.WriteLine("Session not connected. Cannot read.");
                return;
            }

            Debug.WriteLine("Reading value from Tag...");
            var currentValue = opcSession.ReadNodeValue<object>(RequestType);
            Debug.WriteLine($"Value read: {currentValue}");
            Console.WriteLine($"Current Value of RequestType: {currentValue}");
        }

        private void Button_Click_2(object sender, RoutedEventArgs e)
        {
            Debug.WriteLine("Write button clicked.");

            if (opcSession == null)
            {
                Debug.WriteLine("OPC session is null.");
                return;
            }

            if (!opcSession.Connected)
            {
                Debug.WriteLine("Session not connected. Cannot write.");
                return;
            }

            var valueToWrite = 1234;

            Debug.WriteLine($"Attempting to write value '{valueToWrite}' (type: {valueToWrite.GetType()}) to tag: {RequestType.NodeID}");

            try
            {
                opcSession.WriteNodeValue(RequestType, valueToWrite);
                Debug.WriteLine("Write succeeded.");
            }
            catch (Exception ex)
            {
                Debug.WriteLine($"Write failed: {ex.Message}");
            }

            opcSession.WriteNodeValue(RequestType, valueToWrite);


            var before = opcSession.ReadNodeValue<string>(RequestType);
            opcSession.WriteNodeValue(RequestType, "1234");
            var after = opcSession.ReadNodeValue<string>(RequestType);
            Debug.WriteLine($"Before: {before}, After: {after}");
        }
    }
}
