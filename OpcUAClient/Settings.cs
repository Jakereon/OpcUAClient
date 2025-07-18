using CommunityToolkit.Mvvm.ComponentModel;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OpcUAClient
{
    public partial class Settings : ObservableValidator
    {
        [ObservableProperty]
        private string _serverAddress;

        [ObservableProperty]
        private string _serverPort;

        [ObservableProperty]
        private string _oPCNameSpace;

        [ObservableProperty]
        private string _serverPath;

        [ObservableProperty]
        private bool _sessionRenewalRequired;

        [ObservableProperty]

        private double _sessionRenewalPeriodMins;

        [ObservableProperty]

        private bool _securityEnabled;

        [ObservableProperty]

        private string _myApplicationName;
    }
}
