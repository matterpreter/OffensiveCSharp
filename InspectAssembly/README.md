# Notes

The following unsafe methods won't be picked up as they're backed by `XmlObjectSerializer::ReadObject`:
- `DataContractJsonSerializer::ReadObject`
- `DataContractSerializer::ReadObject`
- `NetDataContractSerializer::ReadObject`
