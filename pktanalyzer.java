import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.io.FileNotFoundException;
/*
 * 
 * Foundation of Computer Networks 
 * CSCI 651
 * Project 1
 * 
 * This program an application that reads a set of packets and produces a detailed summary of those 
 * packets. The packet analyzer runs as a shell command. The syntax of the command is the 
 * following: 
 * % java pktanalyzer datafile 
 * 
 * The pktanalyzer program will extract and display the different headers of the captured packets in 
 * the file datafile. First, it displays the ethernet header fields of the captured frames. Second, if the 
 * ethernet frame contains an IP datagram, it prints the IP header. Third, it prints the packets 
 * encapsulated in the IP datagram. TCP, UDP, or ICMP packets can be encapsulated in the IP 
 * packet.
 * 
 * @author Aditya Ajit Tirakannavar (at2650)
 */
public class pktanalyzer {
	// char array of Hex values 
	static final char[] HEX = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9','a', 'b', 'c', 'd', 'e', 'f' };
    public static void main(String[] args) throws FileNotFoundException, IOException {
    	//file path
    	Path path = Paths.get(args[0]);
        byte[] fileContents =  Files.readAllBytes(path);
        //Prints the Ethernet Header
        ethernet_header(fileContents);                                
        //Prints the IP header & calls the protocol function based on the protocol value
        IP_header(fileContents); 
        
    }
	/*
	 * This method converts bytes to Hex using bit wise operators
	 * @param byte
	 */
	private static String bytesToHex(byte Byte){
		return HEX[(0xF0 & Byte) >>> 4] + "" +HEX[(0x0F & Byte)];
	}
	
	/*
	 * This method prints Ethernet header
	 * @param bytes (array) converted from binary file
	 */
	
	private static void ethernet_header(byte[] bytes) {
		//Set size for Ethernet Header
        byte[] ethernet = new byte[14];
		System.arraycopy(bytes, 0, ethernet, 0, 14);
		System.out.println("ETHER: \t----- Ether Header -----\n"+"ETHER:");
		System.out.println("ETHER: \tPacket size:\t" + bytes.length + " bytes");
        System.out.print("ETHER: \tDestination:\t");
        String dest = "";
        for (int i = 0; i < 6; i++) {
            //Single Byte unsignedBytes value conversion to 2-character Hexadecimal
            dest += bytesToHex(ethernet[i]);            
            if (i < 5) {
            	dest += ":";
            }
        }
        System.out.println(dest);
        System.out.print("ETHER: \tSource: \t");
        String src = "";
        for (int i = 6; i < 12; i++) {
        	//Single Byte unsignedBytes value conversion to 2-character Hexadecimal
            src += bytesToHex(ethernet[i]);
            if (i < 11) {
            	src += ":";
            }
        }
        System.out.println(src);
        System.out.print("ETHER: \tEtherType:\t");
        String type = "";
        for (int i = 12; i < 14; i++) {
            //Single Byte unsignedBytes value conversion to 2-character Hexadecimal
            type += bytesToHex(ethernet[i]);
            
        }
        System.out.print(type);
        System.out.println("(IP)");
        
        System.out.println("ETHER: \t");
	}
	/*
	 * This method prints IP header
	 * @param bytes (array) converted from binary file
	 */
	private static void IP_header(byte[] bytes) {
		byte[] ip = new byte[bytes.length-14];
		System.arraycopy(bytes, 14, ip, 0, bytes.length-14);
		System.out.println("IP:\t----- IP Header -----\n"+"IP:");
		byte[] header = new byte[ip.length];
        int[] unsignedBytes = new int[ip.length];
        for(int i=0; i<ip.length; i++) {
        	unsignedBytes[i] = ip[i]&0xff;
        }
        System.out.println("IP:\tVersion: " + (unsignedBytes[0]>>4));
        System.out.println("IP:\tHeader Length: " + (((unsignedBytes[0]&(1<<4)-1)*32)/8) + " bytes");
        System.out.println("IP:\tTypes of Service: 0x" + bytesToHex(ip[1]));
        int precedence = (unsignedBytes[1]>>5);
        
        String precedence_bin = "";
        if((precedence & (1 << (8 - 1) )) > 0) precedence_bin += 1;
        else precedence_bin += 0;

        if((precedence & (1 << (7 - 1) )) > 0) precedence_bin += 1;
        else precedence_bin += 0;

        if((precedence & (1 << (6 - 1) )) > 0) precedence_bin += 1;
        else precedence_bin += 0;

        System.out.println("IP:\t\t "+precedence_bin+". .... = "+precedence+" (precedence)");
        
        if ((unsignedBytes[1]>>4&(1<<1)-1) == 0){
            System.out.println("IP:\t\t "+"...0 .... = Normal Delay");
        }
        else{
            System.out.println("IP:\t\t "+"...1 .... = Low Delay");
        }

        //Extracting first 5 bits and the last bit of the result
        if ((unsignedBytes[1]>>3&(1<<1)-1) == 0){
            System.out.println("IP:\t\t "+".... 0... = Normal Throughput");
        }
        else{
            System.out.println("IP:\t\t "+".... 1... = High Throughput");
        }

        //Extracting first 6 bits and the last bit of the result
        if ((unsignedBytes[1]>>2&(1<<1)-1) == 0){
            System.out.println("IP:\t\t "+".... .0.. = Normal Reliability");
        }
        else{
            System.out.println("IP:\t\t "+".... .1.. = High Reliability");
        }
        
        
        System.out.println("IP:\t"+"Total length:\t " + (unsignedBytes[2]<<8|unsignedBytes[3]) + " bytes");
        System.out.println("IP:\t"+"Identification:\t " + (unsignedBytes[4]<<8|unsignedBytes[5]));
        System.out.println("IP:\tFlags:\t 0x" + (String.format("%02X", unsignedBytes[6]>>5)));
        
        if ((unsignedBytes[6]>>6&(1<<1)-1) == 0){
            System.out.println("IP:\t\t "+".0.. .... = Ok to fragment");
        }
        else{
            System.out.println("IP:\t\t "+".1.. .... = The packet should not be fragmented");
        }

        //Extracting first 3 bits and the last bit of the result
        if ((unsignedBytes[6]>>5&(1<<1)-1) == 0){
            System.out.println("IP:\t\t "+"..0. .... = last fragment");
        }
        else{
            System.out.println("IP:\t\t "+"..1. .... = More Fragments are coming");
        }
        System.out.println("IP:\t"+"Fragment offset: " + (((unsignedBytes[6]&31)<<8)|unsignedBytes[7]) + " bytes");
        System.out.println("IP:\t"+"Time to live: " + unsignedBytes[8] + " seconds/hops");
        System.out.print("IP:\t"+"Protocol: " + unsignedBytes[9]);
        if(unsignedBytes[9] == 6) System.out.println(" (TCP)" );
        else if(unsignedBytes[9] == 1) System.out.println(" (ICMP)" );
        else if(unsignedBytes[9] == 17) System.out.println(" (UDP)" );
        
        
        String header_checksum = "";
        for(int i = 10 ; i< 12 ;i++){
            header_checksum += HEX[(0xF0 & unsignedBytes[i]) >>> 4];
            header_checksum += HEX[(0x0F & unsignedBytes[i])];
        }
        System.out.println("IP: \tHeader Checksum = 0x"+header_checksum);
        System.out.println("IP: \tSource IP address:IP: \t " + unsignedBytes[12] + "." + unsignedBytes[13] + "." + unsignedBytes[14] + "." + unsignedBytes[15]);
        System.out.println("IP: \tDestination IP address: IP: \t" + unsignedBytes[16] + "." + unsignedBytes[17] + "." + unsignedBytes[18] + "." + unsignedBytes[19]);
        if ((unsignedBytes[0]&(1<<4)-1) > 5) {
            int length = ((unsignedBytes[0]&(1<<4)-1)*32)/8;
            int option_length = length - 20;
            //Copy the payload of IP header, skipping the options field for further analysis
            System.arraycopy(ip, 20 + option_length, header, 0, ip.length - length);
            System.out.println("IP: \tOptions length :IP: \t" + option_length + " bytes");
        } else {
            //Copy the payload of IP header. Options field is not present.
            System.arraycopy(ip, 20, header, 0, ip.length - 20);
            System.out.println("IP: \tNo options");
        }
        System.out.println("IP: \t");
        if(unsignedBytes[9] == 1) ICMP(header);
		else if(unsignedBytes[9] == 6) TCP(header);
		else if(unsignedBytes[9] == 17) UDP(header);
	}
	/*
	 * This method prints ICMP header
	 * @param bytes (array) converted from binary file except the first 34 bytes
	 */
	private static void ICMP(byte[] bytes) {
		int[] unsignedBytes = new int[bytes.length];
        //Converting signed bytes to unsigned bytes by 2's complement
        for(int i=0; i<bytes.length; i++) {
        	unsignedBytes[i] = bytes[i]& 0xff;
        }
        System.out.println("ICMP:\t"+"----- ICMP Header -----\n"+"ICMP:\t");
        System.out.println("ICMP:\t"+"Type: " + (unsignedBytes[0])+" (Echo Request)");
        System.out.println("ICMP:\t"+"Code: " + (unsignedBytes[1]));
        //Combining two bytes from byte[]
        System.out.println("ICMP:\t"+"ICMP Checksum: 0x" + (String.format("%02x", (unsignedBytes[2]<<8)|(unsignedBytes[3]))));
    }
		
	/*
	 * This function prints the UDP header which contains Source port, Destination port, Length, CHecksum and payload
	 * @param bytes (array) converted from binary file except the first 34 bytes
	 */
	private static void UDP(byte[] bytes) {
        int[] unsignedBytes = new int[bytes.length];
        //Converting signed bytes to unsigned bytes by 2's complement
        for(int i=0; i<bytes.length; i++) {
            unsignedBytes[i] = bytes[i]&0xff;
        }
        
        System.out.println("UDP:\t"+"----- UDP Header -----");
        //Combining two bytes from byte[]
        System.out.println("UDP:\t"+"Source port: " + ((unsignedBytes[0]<<8)|unsignedBytes[1]));
        //Combining two bytes from byte[]
        System.out.println("UDP:\t"+"Destination port: " + ((unsignedBytes[2]<<8)|unsignedBytes[3]));
        //Combining two bytes from byte[]
        System.out.println("UDP:\t"+"Length: " + ((unsignedBytes[4]<<8)|unsignedBytes[5]));
        //Combining two bytes from byte[]
        System.out.println("UDP:\t"+"Checksum: 0x" + (String.format("%02X", (unsignedBytes[6]<<8)| unsignedBytes[7])));
        //UDP header length is 8. Check for the length of data field in UDP packet
        byte[] data = new byte[unsignedBytes.length - 8];
        //Integer values are not needed, so no need to convert signed to unsigned.
        System.arraycopy(bytes, 8, data, 0, data.length);        
        System.out.println("UDP: \t Data: (first 64 bytes)");
        String hexval ="";
        //printing at most 64 bytes
        for (int i1 = 8; i1<unsignedBytes.length; i1++) {
            hexval+=(String.format("%02X", (unsignedBytes[i1])));            
        }
        System.out.print("TCP:\t");
        printdata(hexval,"UDP");
        
        }
	
	
	/*
	 * This function prints the data bytes(converted to Hex) into readable format
	 * @param hex value of payload and protocol name (TCP/UDP)
	 */
	private static void printdata(String hexval, String protocol) {
		{
	        int counter = 0;
	        String oneLine = "";
	        String format = "";
	        if(protocol == "TCP")
	            format = "TCP:\t";
	        if(protocol == "UDP")
	            format = "UDP:\t";
	        for(int i=0; i<hexval.length();i++)
	        {
	            counter++;
	            System.out.print(hexval.charAt(i));
	            if(counter%4 ==0)
	                System.out.print(" ");              //for a space between two hex characters
	            oneLine += hexval.charAt(i);
	            if(counter%32==0||i==hexval.length()-1)      //end of line
	            {
	                System.out.print(" \" ");
	                for(int j=0; j<oneLine.length(); j+=2)
	                {
	                    if(Integer.parseInt(oneLine.substring(j, j+2), 16)>=33 && Integer.parseInt(oneLine.substring(j, j+2), 16)<=127) //readable range of ASCII values (Alphanumeric values with punctuation and other symbols)
	                    {
	                        System.out.print(Character.toString((char)Integer.parseInt(oneLine.substring(j, j+2), 16)));        //prints the data in readable format
	                    }
	                    else
	                        System.out.print(".");//skips the hex
	                }
	                System.out.print(" \" ");
	                System.out.println();
	                System.out.print(format);
	                oneLine = "";
	            }

	            if(counter==128)          //to maintain only 64 bytes of data
	                break;

	        }
	    }
		
	}
	
	/*
	 * This function prints the TCP header and it takes input as array of bytes
	 * @param bytes (array) converted from binary file except the first 34 bytes
	 */

	private static void TCP(byte[] bytes) {
        byte[] TCPdata = new byte[bytes.length];

        int[] unsignedBytes = new int[bytes.length];
        //Converting signed bytes to unsigned bytes by 2's complement
        for(int i=0; i<bytes.length; i++) {
            unsignedBytes[i] = bytes[i]&0xff;
        }

        System.out.println("TCP:\t -------TCP Header-------");
        //Combining two bytes from byte[]
        System.out.println("TCP:\tSource port: " + ((unsignedBytes[0]<<8)|unsignedBytes[1]));
        //Combining two bytes from byte[]
        System.out.println("TCP:\t"+"Destination port: " + ((unsignedBytes[2]<<8)|unsignedBytes[3]));
        //Combining four bytes from byte[]
        System.out.println("TCP:\t"+"Sequence Number: " + ((unsignedBytes[4]<<24)|(unsignedBytes[5]<<16)| (unsignedBytes[6]<<8)|unsignedBytes[7]));
        //Combining four bytes from byte[]
        System.out.println("TCP:\t"+"Acknowledgement Number: " + (((unsignedBytes[8]<<24)| (unsignedBytes[9]<<16)|(unsignedBytes[10]<<8)|unsignedBytes[11])));
        //Extracting first four bits --> Header Length
        System.out.println("TCP:\t"+"Data Offset: " + (unsignedBytes[12]>>4&(1<<4)-1) + "*32 = 256 bits/8 = 32 bytes");
        //Combining last six bits of one byte from byte[]
        System.out.println("TCP:\t"+"Flags: 0x" + (String.format("%02X", ((unsignedBytes[13]&((1<<6)-1))))));
        //Extracting first 3 bits and the last bit of the result
        if ((unsignedBytes[13]>>5&(1<<1)-1) == 0){
            System.out.println("TCP:\t"+"\t"+"..0. .... = No Urgent Pointer");
        }
        else{
            System.out.println("TCP:\t"+"\t"+"..1. .... = Urgent Pointer");
        }
        //Extracting first 4 bits and the last bit of the result
        if ((unsignedBytes[13]>>4&(1<<1)-1) == 0){
            System.out.println("TCP:\t"+"\t"+"...0 .... = No Acknowledgement");
        }
        else{
            System.out.println("TCP:\t"+"\t"+"...1 .... = Acknowledgement");
        }
        //Extracting first 5 bits and the last bit of the result
        if ((unsignedBytes[13]>>3&(1<<1)-1) == 0){
            System.out.println("TCP:\t"+".... 0... = No Push Request");
        }
        else{
            System.out.println("TCP:\t"+"\t"+".... 1... = Push Request");
        }
        //Extracting first 6 bits and the last bit of the result
        if ((unsignedBytes[13]>>2&(1<<1)-1) == 0){
            System.out.println("TCP:\t"+"\t"+".... .0.. = No Reset");
        }
        else{
            System.out.println("TCP:\t"+"\t"+".... .1.. = Reset");
        }
        //Extracting first 7 bits and the last bit of the result
        if ((unsignedBytes[13]>>1&(1<<1)-1) == 0){
            System.out.println("TCP:\t"+"\t"+".... ..0. = No Syn");
        }
        else{
            System.out.println("TCP:\t"+"\t"+".... ..1. = Syn");
        }
        //Extracting first 8 bits and the last bit of the result
        if ((unsignedBytes[13]&(1<<1)-1) == 0){
            System.out.println("TCP:\t"+"\t"+".... ...0 = No Fin");
        }
        else{
            System.out.println("TCP:\t"+"\t"+".... ...1 = Fin");
        }
        //Combining two bytes from byte[]
        System.out.println("TCP:\t"+"Window: " + ((unsignedBytes[14]<<8)|unsignedBytes[15]));
        //Combining two bytes from byte[]
        System.out.println("TCP:\t"+"Checksum: 0x" + (String.format("%02X", (unsignedBytes[16]<<8)|
                (unsignedBytes[17]))));
        //Combining two bytes from byte[]
        System.out.println("TCP:\t"+"Urgent Pointer: " + ((unsignedBytes[18]<<8)|unsignedBytes[19]));
        //Check if Options for TCP header exists by checking the condition Header Length > 5

        if (unsignedBytes[12]>>4 >5) {
            int length_val = (int) ((unsignedBytes[12]>>4)*32)/8;
            int option_length = length_val - 20;
            //Copy the payload of TCP header, skipping the options field for further analysis
            System.arraycopy(bytes, 20 + option_length, TCPdata, 0, unsignedBytes.length - length_val);
            System.out.println("TCP:\t"+"Options length:" + option_length + " bytes");
        } else {
            //Copy the payload of TCP header. Options field is not present.
            System.arraycopy(bytes, 20, TCPdata, 0, unsignedBytes.length - 20);
            System.out.println("TCP:\t"+"TCP Header has No options");
        }

        System.out.println("TCP:" +"\tData:\t(first 64 bytes)");
        String hexval="";
      //printing at most 64 bytes
        for (int i1 = 8; i1<unsignedBytes.length; i1++) {
            hexval+=(String.format("%02X", (unsignedBytes[i1])));            
        }
        System.out.print("TCP:\t");
        printdata(hexval,"TCP");  
        
	}
	
	

}
