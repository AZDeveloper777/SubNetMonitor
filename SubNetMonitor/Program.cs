﻿using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Management;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.ServiceProcess;

//Intended for use with a tool like Suricata
//Tested on Windows 10.
//Use case:  Suricata tells you a machine is making calls to a given IP address and you don't know what program is doing that.
//           Put the subnet for that IP address in a file called subnets.txt in your executable directory.
//           Run the console app and wait for it to output the path/executable that calls that subnet.

class Program
{
    const int AF_INET = 2; // IPv4

    [StructLayout(LayoutKind.Sequential)]
    struct MIB_TCPROW_OWNER_PID
    {
        public uint dwState;
        public uint dwLocalAddr;
        public uint dwLocalPort;
        public uint dwRemoteAddr;
        public uint dwRemotePort;
        public uint dwOwningPid;
    }

    [DllImport("iphlpapi.dll", SetLastError = true)]
    static extern uint GetExtendedTcpTable(IntPtr pTcpTable, ref int dwSize, bool bOrder, int ulAf, TcpTableClass tableClass, uint reserved = 0);

    enum TcpTableClass
    {
        TCP_TABLE_BASIC_LISTENER,
        TCP_TABLE_BASIC_CONNECTIONS,
        TCP_TABLE_BASIC_ALL,
        TCP_TABLE_OWNER_PID_LISTENER,
        TCP_TABLE_OWNER_PID_CONNECTIONS,
        TCP_TABLE_OWNER_PID_ALL,
        TCP_TABLE_OWNER_MODULE_LISTENER,
        TCP_TABLE_OWNER_MODULE_CONNECTIONS,
        TCP_TABLE_OWNER_MODULE_ALL
    }

    static void Main()
    {
        Console.WriteLine("Monitoring processes with network connections to specified subnets. Press Ctrl+C to exit.");

        List<string> subnets = ReadSubnetsFromFile("subnets.txt");

        Console.WriteLine("--------------------------------------"); 

        foreach (string subnet in subnets)
        {
            Console.WriteLine(subnet);
            
        }

        Console.WriteLine("--------------------------------------");

        // Start a thread to continuously monitor processes
        Thread monitoringThread = new Thread(() =>
        {
            while (true)
            {
                MonitorProcesses(subnets);
                Thread.Sleep(TimeSpan.FromSeconds(5)); // Adjust the delay as needed
            }
        });

        monitoringThread.Start();

        // Keep the main thread running
        Console.ReadLine();
    }

    static void MonitorProcesses(List<string> subnets)
    {
        Process[] processes = Process.GetProcesses();

        foreach (var process in processes)
        {
            var retIpAddress = HasNetworkConnectionToSubnets(process.Id, subnets);
            if (retIpAddress != "")
            {
                
                if (process.ProcessName.ToLower() == "svchost")
                {
                    // Get the services associated with the svchost process
                    ServiceController[] services = ServiceController.GetServices();

                    // Iterate through each service and check if it's associated with the current svchost process
                    foreach (ServiceController service in services)
                    {
                        if (IsServiceAssociatedWithProcess(service, process.Id))
                        {
                            Console.WriteLine($"IP Address: {retIpAddress} ,Service Name: {service.ServiceName}, Display Name: {service.DisplayName}");
                        }
                    }
                }
                else
                {
                    Console.WriteLine(DateTime.Now.ToString() + $"IP Address:  {retIpAddress}, Process Name: {process.ProcessName}");
                }
            }
        }
    }

    static string HasNetworkConnectionToSubnets(int processId, List<string> subnets)
    {
        try
        {
            int bufferSize = 0;
            GetExtendedTcpTable(IntPtr.Zero, ref bufferSize, false, AF_INET, TcpTableClass.TCP_TABLE_OWNER_PID_ALL);

            IntPtr tcpTablePtr = Marshal.AllocCoTaskMem(bufferSize);
            try
            {
                if (GetExtendedTcpTable(tcpTablePtr, ref bufferSize, false, AF_INET, TcpTableClass.TCP_TABLE_OWNER_PID_ALL) == 0)
                {
                    int rowSize = Marshal.SizeOf(typeof(MIB_TCPROW_OWNER_PID));
                    int rowCount = Marshal.ReadInt32(tcpTablePtr);

                    for (int i = 0; i < rowCount; i++)
                    {
                        IntPtr rowPtr = IntPtr.Add(tcpTablePtr, 4 + i * rowSize);
                        MIB_TCPROW_OWNER_PID row = Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID>(rowPtr);
                        string retIpAddress = IsRemoteAddressInSubnets(row.dwRemoteAddr, subnets);

                        if (row.dwOwningPid == processId && retIpAddress != "")
                        {
                            return retIpAddress;
                        }
                    }
                }
            }
            finally
            {
                Marshal.FreeCoTaskMem(tcpTablePtr);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error checking network connections: {ex.Message}");
        }

        return "";
    }

    static string IsRemoteAddressInSubnets(uint remoteAddress, List<string> subnets)
    {
        string remoteIpAddress = GetIPAddress(remoteAddress);

        foreach (string subnet in subnets)
        {
            if (IsIPInSubnet(remoteIpAddress, subnet))
            {
                return remoteIpAddress;
            }
        }

        return "";
    }

    static bool IsIPInSubnet(string ipAddress, string subnet)
    {
        IPAddress ip = IPAddress.Parse(ipAddress);
        IPNetwork network = IPNetwork.Parse(subnet);

        return IPNetwork.Contains(network, ip);
    }

    static string GetIPAddress(uint ipAddress)
    {
        return $"{(ipAddress & 0xFF)}.{((ipAddress >> 8) & 0xFF)}.{((ipAddress >> 16) & 0xFF)}.{((ipAddress >> 24) & 0xFF)}";
    }

    static List<string> ReadSubnetsFromFile(string filePath)
    {
        try
        {
            return File.ReadAllLines(filePath).ToList();
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error reading subnets from file: {ex.Message}");
            return new List<string>();
        }
    }

    static bool IsServiceAssociatedWithProcess(ServiceController service, int processId)
    {
        try
        {
            // Get the Win32OwnProcess property using WMI to check if the service is associated with the given process ID
            using (ManagementObjectSearcher searcher = new ManagementObjectSearcher($"SELECT * FROM Win32_Service WHERE ProcessId = {processId}"))
            {
                foreach (ManagementObject obj in searcher.Get())
                {
                    if (obj["Name"].ToString() == service.ServiceName)
                    {
                        return true;
                    }
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error checking service association: {ex.Message}");
        }

        return false;
    }
}
