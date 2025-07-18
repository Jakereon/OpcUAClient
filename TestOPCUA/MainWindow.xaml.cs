using System.Diagnostics;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using Opc.Ua;
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
        public static Tag RequestType => new Tag("CEL_FBC_COUNTER_01.RequestType", "ns=2;s=CEL_FBC_COUNTER_01.Controller.RequestType");


        private void Button_Click(object sender, RoutedEventArgs e)
        {
            Debug.WriteLine("Connect button clicked.");

            // Create settings
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
                SecurityEnabled = false 
            };

            Debug.WriteLine("Creating new OPCSession instance.");
            opcSession = new OPCSession(settings);
            opcSession.TagList.Add(RequestType);
            Debug.WriteLine("TestTag added to TagList.");

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

            var valueToWrite = "1234";

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
            opcSession.WriteNodeValue(RequestType, "TEST_ABC");
            var after = opcSession.ReadNodeValue<string>(RequestType);
            Debug.WriteLine($"Before: {before}, After: {after}");
        }
    }
}
