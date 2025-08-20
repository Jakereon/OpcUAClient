using Opc.Ua;
using System;

namespace OpcUAClient
{
    /// <summary>
    /// Represents an OPC UA tag, including value, timestamps, and change notification.
    /// </summary>
    public class Tag
    {
        /// <summary>
        /// The display name of the tag (user-friendly).
        /// </summary>
        public string DisplayName { get; set; }

        /// <summary>
        /// The OPC UA NodeID for this tag.
        /// </summary>
        public string NodeID { get; set; }

        /// <summary>
        /// The last time the tag value was updated.
        /// </summary>
        public DateTime LastUpdatedTime { get; set; }

        /// <summary>
        /// The OPC UA SourceTimestamp of the last update.
        /// </summary>
        public DateTime LastSourceTimeStamp { get; set; }

        /// <summary>
        /// The OPC UA StatusCode of the last read.
        /// </summary>
        public string StatusCode { get; set; }

        /// <summary>
        /// The last good (non-bad) value of the tag.
        /// </summary>
        public string LastGoodValue { get; set; }

        /// <summary>
        /// The current value of the tag.
        /// </summary>
        public string CurrentValue { get; set; }

        /// <summary>
        /// Event triggered when the tag's value is changed.
        /// </summary>
        public event Action<Tag> ValueChanged;

        /// <summary>
        /// Raises the <see cref="ValueChanged"/> event.
        /// </summary>
        internal void RaiseValueChanged()
        {
            ValueChanged?.Invoke(this);
        }

        /// <summary>
        /// Parameterless constructor to support object initializer syntax.
        /// </summary>
        public Tag() { }

        /// <summary>
        /// Constructor with display name and node ID.
        /// </summary>
        /// <param name="displayName">The display name of the tag.</param>
        /// <param name="nodeID">The OPC UA NodeID.</param>
        public Tag(string displayName, string nodeID)
        {
            DisplayName = displayName;
            NodeID = nodeID;
        }



        // In your Tag class:
        public NodeId ExpectedDataTypeId { get; set; }          // UA DataType NodeId (e.g., UInt32)
        public int ExpectedValueRank { get; set; } = ValueRanks.Scalar; // Scalar or array rank
        public object CurrentValueObj { get; set; }              // Preserve real CLR value
        public BuiltInType? CurrentBuiltInType { get; set; }     // Convenience (e.g., UInt32, Double)
        public TypeInfo CurrentTypeInfo { get; set; }            // UA TypeInfo of current value
    }
}
