using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace OpcUAClient
{
    public class TagValueChangedEventArgs : EventArgs
    {
        public string TagName { get; }
        public string NewValue { get; }
        public DateTime Timestamp { get; }

        public TagValueChangedEventArgs(string tagName, string newValue, DateTime timestamp)
        {
            TagName = tagName;
            NewValue = newValue;
            Timestamp = timestamp;
        }
    }
}
