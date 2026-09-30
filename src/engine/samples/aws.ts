/** AWS VPC security-group export — demonstrates structured (JSON) ingestion. */
export const SAMPLE_AWS_SG = `{
  "SecurityGroups": [
    {
      "GroupName": "prod-web-sg",
      "GroupId": "sg-0a1b2c3d4e5f60718",
      "Description": "Production web tier",
      "VpcId": "vpc-0f1e2d3c4b5a69788",
      "OwnerId": "123456789012",
      "IpPermissions": [
        {
          "IpProtocol": "tcp",
          "FromPort": 443,
          "ToPort": 443,
          "IpRanges": [ { "CidrIp": "0.0.0.0/0", "Description": "public https" } ]
        },
        {
          "IpProtocol": "tcp",
          "FromPort": 22,
          "ToPort": 22,
          "IpRanges": [ { "CidrIp": "0.0.0.0/0", "Description": "ssh from anywhere" } ]
        },
        {
          "IpProtocol": "tcp",
          "FromPort": 23,
          "ToPort": 23,
          "IpRanges": [ { "CidrIp": "10.10.0.0/24", "Description": "legacy telnet" } ]
        }
      ],
      "IpPermissionsEgress": [
        { "IpProtocol": "-1", "IpRanges": [ { "CidrIp": "0.0.0.0/0" } ] }
      ],
      "Tags": [
        { "Key": "Environment", "Value": "prod" },
        { "Key": "Owner", "Value": "netops@example.in" }
      ]
    }
  ]
}
`;
