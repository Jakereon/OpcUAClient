using Opc.Ua;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OpcUAClient
{
    public class AlarmEventArgs : EventArgs
    {
        public NodeId NodeId { get; }
        public object AlarmState { get; }

        public AlarmEventArgs(NodeId nodeId, object alarmState)
        {
            NodeId = nodeId;
            AlarmState = alarmState;
        }
    }
}
