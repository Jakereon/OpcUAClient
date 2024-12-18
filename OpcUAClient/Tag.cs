using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OpcUAClient
{
    public class Tag
    {
        public string DisplayName { get; set; }
        public string NodeID { get; set; }
        public DateTime LastUpdatedTime { get; set; }
        public DateTime LastSourceTimeStamp { get; set; }
        public string StatusCode { get; set; }
        public string LastGoodValue { get; set; }
        public string CurrentValue { get; set; }

        public Tag(string displayName, string nodeID)
        {
            DisplayName = displayName;
            NodeID = nodeID;
        }
    }
}
