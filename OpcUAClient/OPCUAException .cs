using System;

namespace OpcUAClient
{
    /// <summary>
    /// Represents errors that occur during OPC UA operations.
    /// </summary>
    public class OPCUAException : Exception
    {
        /// <summary>
        /// Gets the OPC UA node associated with the error, if applicable.
        /// </summary>
        public string NodeId { get; }

        /// <summary>
        /// Gets the OPC UA operation that caused the error, if applicable.
        /// </summary>
        public string Operation { get; }

        /// <summary>
        /// Initializes a new instance of the <see cref="OPCUAException"/> class.
        /// </summary>
        public OPCUAException()
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="OPCUAException"/> class with a specified error message.
        /// </summary>
        /// <param name="message">The message that describes the error.</param>
        public OPCUAException(string message)
            : base(message)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="OPCUAException"/> class with a specified error message and a reference to the inner exception that is the cause of this exception.
        /// </summary>
        /// <param name="message">The message that describes the error.</param>
        /// <param name="innerException">The exception that is the cause of the current exception.</param>
        public OPCUAException(string message, Exception innerException)
            : base(message, innerException)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="OPCUAException"/> class with a message, operation, and inner exception.
        /// </summary>
        /// <param name="message">The error message.</param>
        /// <param name="operation">The operation being performed when the error occurred.</param>
        /// <param name="innerException">The inner exception that caused this exception.</param>
        public OPCUAException(string message, string operation, Exception innerException)
            : base(message, innerException)
        {
            Operation = operation;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="OPCUAException"/> class with a specified message and operation.
        /// </summary>
        /// <param name="message">The error message.</param>
        /// <param name="operation">The name of the operation.</param>
        public OPCUAException(string message, string operation)
            : base(message)
        {
            Operation = operation;
        }

        public OPCUAException(string message, string operation, string nodeId)
    : base(message)
        {
            Operation = operation;
            NodeId = nodeId;
        }

        public OPCUAException(string message, string operation, string nodeId, Exception innerException)
    : base(message, innerException)
        {
            Operation = operation;
            NodeId = nodeId;
        }


        /// <summary>
        /// Returns a string representation of the exception with detailed context.
        /// </summary>
        /// <returns>A string representation of the exception.</returns>
        public override string ToString()
        {
            var runtimeMessage = base.InnerException.ToString();
            var baseMessage = base.ToString();
            var nodeInfo = !string.IsNullOrEmpty(NodeId) ? $"NodeId: {NodeId}" : "NodeId: Not specified";
            var operationInfo = !string.IsNullOrEmpty(Operation) ? $"Operation: {Operation}" : "Operation: Not specified";
            return $"{runtimeMessage}{Environment.NewLine}{baseMessage}{Environment.NewLine}{nodeInfo}{Environment.NewLine}{operationInfo}";
        }
    }
}
