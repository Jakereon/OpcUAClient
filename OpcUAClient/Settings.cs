using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OpcUAClient
{
    using System.ComponentModel;

    public class Settings : INotifyPropertyChanged
    {
        private string _serverAddress;
        public string ServerAddress
        {
            get { return _serverAddress; }
            set
            {
                if (_serverAddress != value)
                {
                    _serverAddress = value;
                    OnPropertyChanged(nameof(ServerAddress));
                }
            }
        }

        private string _serverPort;
        public string ServerPort
        {
            get { return _serverPort; }
            set
            {
                if (_serverPort != value)
                {
                    _serverPort = value;
                    OnPropertyChanged(nameof(ServerPort));
                }
            }
        }

        private string _oPCNameSpace;
        public string OPCNameSpace
        {
            get { return _oPCNameSpace; }
            set
            {
                if (_oPCNameSpace != value)
                {
                    _oPCNameSpace = value;
                    OnPropertyChanged(nameof(OPCNameSpace));
                }
            }
        }

        private string _serverPath;
        public string ServerPath
        {
            get { return _serverPath; }
            set
            {
                if (_serverPath != value)
                {
                    _serverPath = value;
                    OnPropertyChanged(nameof(ServerPath));
                }
            }
        }

        private bool _sessionRenewalRequired;
        public bool SessionRenewalRequired
        {
            get { return _sessionRenewalRequired; }
            set
            {
                if (_sessionRenewalRequired != value)
                {
                    _sessionRenewalRequired = value;
                    OnPropertyChanged(nameof(SessionRenewalRequired));
                }
            }
        }

        private double _sessionRenewalPeriodMins;
        public double SessionRenewalPeriodMins
        {
            get { return _sessionRenewalPeriodMins; }
            set
            {
                if (_sessionRenewalPeriodMins != value)
                {
                    _sessionRenewalPeriodMins = value;
                    OnPropertyChanged(nameof(SessionRenewalPeriodMins));
                }
            }
        }

        private bool _securityEnabled;
        public bool SecurityEnabled
        {
            get { return _securityEnabled; }
            set
            {
                if (_securityEnabled != value)
                {
                    _securityEnabled = value;
                    OnPropertyChanged(nameof(SecurityEnabled));
                }
            }
        }

        private string _myApplicationName;
        public string MyApplicationName
        {
            get { return _myApplicationName; }
            set
            {
                if (_myApplicationName != value)
                {
                    _myApplicationName = value;
                    OnPropertyChanged(nameof(MyApplicationName));
                }
            }
        }

        // Classic INotifyPropertyChanged implementation:
        public event PropertyChangedEventHandler PropertyChanged;
        protected void OnPropertyChanged(string propertyName)
        {
            var handler = PropertyChanged;
            if (handler != null)
                handler(this, new PropertyChangedEventArgs(propertyName));
        }
    }

}
