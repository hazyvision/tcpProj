
//Adriene Cuenco
//Initial branch (For data Size = 2 only)

import java.io.*;
import java.net.*;
import java.util.*;
import java.nio.ByteBuffer;

import javax.xml.bind.DatatypeConverter;

	
public class TcpClient {
    //Initialize Global Variables
    static byte version = 4;
    static byte hlen = 5;
    static byte tos = 0;
    static short tLen = 0;
    static short iden = 0;
    static int flags =0x4000;
    static byte ttl = 50;
    static byte protocol = 6; //tcp = 6
    static short checksum = 0;
    static int srcAddress = 0xC0A811A; //192.168.1.26
    static int destAddress = 0x4C5B7B61; //76.91.123.97
    
    static short fillerPort =0x420;
    static int sequenceNum = 3232;
    static byte dataOffset = 5;
    static byte reserved = 0;
    static byte flagsTCP = 0b00000010;
    static short windowSize = 0;
    static short urgentPointer = 0;

    
	public static void main(String[] args) {
		try(Socket socket = new Socket("76.91.123.97", 38006)){
			System.out.println("Connected to server successfully...");
			System.out.println(socket);
			System.out.println("------------------------------------------------------");
			
			OutputStream out = socket.getOutputStream();
			InputStream in = socket.getInputStream();
			
			int dataSize = 2;
			System.out.println("Data Size: " + dataSize);
			
			//Creating syn packet-----------------------------------------------------------
			//byte[] data = generateRandomData(dataSize); 
			//byte[] tcpHeader = generateTcp(data);
			//byte[] ipv4Header = generateIpv4(tcpHeader);
			byte[] ipv4Header = generateIpv4(generateTcp(generateRandomData(2)));
			
			out.write(ipv4Header);
			System.out.println("packet sent Checkpoint");
			byte[] synPacket = new byte[4];
			in.read(synPacket);
			System.out.println("synPacket> " +  DatatypeConverter.printHexBinary(synPacket));
			//SYN packet complete------------------------------------------------------------
				
		}
		catch(Exception e){
			System.out.println("Possible problems: ");
			System.out.println("1)Incorrect address/port");
			System.out.println("2)Socket is unavailable");
			System.out.println("3)Socket timed out");
			System.out.println("4)Offline");
			System.out.println("Socket is closing...");
		}
	} // End Main
	
	public static byte[] generateIpv4(byte[] data){
		byte[] header = new byte[20 + data.length];
		System.out.println("generateIpv4 Checkpoint");
		//reset checksum
		checksum = 0;
		
	
		//Wrap header in Bytebuffer
		ByteBuffer headerBuf = ByteBuffer.wrap(header);
		headerBuf.put((byte) ((version & 0xf) << 4 | hlen & 0xf));
		headerBuf.put(tos);
        tLen = (short)(20 + data.length);
        headerBuf.putShort(tLen);
        headerBuf.putShort(iden);
        headerBuf.putShort((short) flags);
        headerBuf.put(ttl);
        headerBuf.put(protocol);
        headerBuf.putShort(checksum);
        headerBuf.putInt(srcAddress);
        headerBuf.putInt(destAddress);
        checksum = (byte) checksum_Funct(headerBuf,hlen);
        headerBuf.put(data);		
		return header;
	} //End Function generateIpv4
	
	public static byte[] generateTcp(byte data[]){
		System.out.println("generateTCP Checkpoint");
		int tcpHlen = 20 /*+ data.length*/;
		byte[] header = new byte[tcpHlen];
		ByteBuffer headerBuf = ByteBuffer.wrap(header);
		checksum = 0;
		
		/*
	    short fillerPort =0x420;
	    int sequenceNum = 3232;
	    byte dataOffset = 5;
	    byte reserved = 0;
	    byte flagsTCP = 0b00000010;
	    short windowSize = 0;
	    short urgentPointer = 0;
		*/
		headerBuf.putShort((short)fillerPort);//Random Source Port
		headerBuf.putShort((short)fillerPort); //Random Dest Port
		headerBuf.putInt(sequenceNum);   //Random sequence number
		headerBuf.putInt(0); // Acknowledgment number (if ACK set)
		headerBuf.put((byte) ((dataOffset & 0xF) << 4 | reserved & 0xF) ); //NS flag = 0(Built in reserve)	
		//Flags --> [cwr,ece,urg,ack,psh,rst,syn,fin] *Note: not including NS flag. Look above^^
		headerBuf.put((byte) flagsTCP);
		headerBuf.putShort(windowSize);
		//------Begin PseudoHeaderTCP-----------------------------------------------------------
		//short pseudoHlen = 8;
		//byte[] pHeader = new byte[(pseudoHlen * 4) + data.length];
		byte[] pHeader = new byte[20];
		ByteBuffer pHeaderBuf = ByteBuffer.wrap(pHeader);
		//pHeaderBuf.putInt(srcAddress);
		//pHeaderBuf.putInt(destAddress);
		//pHeaderBuf.put((byte) 0); // Zeros
		//pHeaderBuf.put(protocol);
		//pHeaderBuf.putShort((short) pHeader.length);
		pHeaderBuf.putShort(fillerPort);
		pHeaderBuf.putShort(fillerPort);
		pHeaderBuf.putInt(sequenceNum);
		pHeaderBuf.putInt(0);
		pHeaderBuf.put((byte) ((dataOffset & 0xF) << 4 | reserved & 0xF) );
		pHeaderBuf.put((byte) flagsTCP);
		pHeaderBuf.putShort(windowSize);
		pHeaderBuf.putShort(checksum);
		pHeaderBuf.putShort(urgentPointer);
		//pHeaderBuf.put(data);
		//System.out.println("pHeaderBuf.capacity()/4: " + pHeaderBuf.capacity()/4.0);
		System.out.println("Right before checksum_Funct_TCP Checkpoint");
		checksum = (byte) checksum_Funct_TCP(pHeaderBuf,(byte) 5,10);
	
		//checksum = checksum_Funct2(pHeaderBuf,(byte) hlen);
		//------End PseudoHeaderTCP-------------------------------------------------------------
		headerBuf.putShort(checksum);
		headerBuf.putShort(urgentPointer);
		//headerBuf.put(data);
		System.out.println("Done generateTCP Checkpoint");
		return header;
	}// end Function generateTcp
	
	public static short checksum_Funct(ByteBuffer bb, byte hlen){
		System.out.println("checksum_Funct Checkpoint");
	    int num = 0;
	    bb.rewind();
	    for(int i = 0; i < hlen*2; ++i){
	      num += 0xFFFF & bb.getShort();
	    }
	    num = ((num >> 16) & 0xFFFF) + (num & 0xFFFF);
	    checksum = (short) (~num & 0xFFFF);
	    bb.putShort(10,checksum);
	    return checksum;
	}//end checksum_Funct
	
    public static short checksum_Funct_TCP(ByteBuffer header,int hlen,int tcpHlen){
    	System.out.println("checksum_Funct_TCP Checkpoint");
    	 int sum = 0;
    	 header.rewind();
    	 //sum pseudo header
		 sum += ((srcAddress >> 16) & 0xFFFF) + (srcAddress & 0xFFFF);
		 sum += ((destAddress >> 16) & 0xFFFF) + (destAddress & 0xFFFF);
		 sum += (byte) protocol & 0xFFFF;
		 sum += (short)(20) & 0xFFFF;
		 //experimental start
		 sum+= (short) fillerPort & 0xFFFF;
		 sum+= (short) fillerPort & 0xFFFF;
		 sum+= ((sequenceNum >> 16) & 0xFFFF) + (sequenceNum & 0xFFFF);
		 //sum+= (((sequenceNum+1) >> 16) & 0xFFFF) + ((sequenceNum+1) & 0xFFFF);
		 ByteBuffer tempBuf = ByteBuffer.allocate(16);
		 tempBuf.put((byte) ((dataOffset & 0xF) << 4 | reserved & 0xF) );
		 tempBuf.put((byte) flagsTCP);
		 tempBuf.rewind();
		 sum += 0xFFFF & tempBuf.getShort();
		 sum += (short) windowSize & 0xFFFF;
		 sum += (short) checksum & 0xFFFF;
		 sum += (short) urgentPointer & 0xFFFF;
		 //experimental end
		 /*
		 System.out.println("Checkpoint 1");
		 //Sum tcp segment
		 for (int i = 0; i < hlen*2 ; i++){
		   sum += 0xFFFF & header.getShort();
		 }    
		 System.out.println("Checkpoint2");
		 // if length is odd
		 if(hlen % 2 > 0){
		   sum += (header.get() & 0xFF) << 8;
		 }
		 */
		 sum = ((sum >> 16) & 0xFFFF) + (sum & 0xFFFF);
		 short result = (short) (~sum & 0xFFFF);
		 System.out.println("Sum: " + result);
		 return result;
  }// End Function checksum_Funct_TCP
	
	public static byte[] generateRandomData(int size){
		Random r = new Random();
		byte[] randomArr = new byte[size];
		for (int i = 0; i < size; i++){
			randomArr[i] = (byte)r.nextInt();
		}
		return randomArr;
	} // end Function generateRandomData

	

} // End Class TcpClient
