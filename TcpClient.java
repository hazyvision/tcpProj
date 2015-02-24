
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
    
	public static void main(String[] args) {
		try(Socket socket = new Socket("76.91.123.97", 38006)){
			System.out.println("Connected to server successfully...");
			System.out.println(socket);
			System.out.println("------------------------------------------------------");
			
			OutputStream out = socket.getOutputStream();
			InputStream in = socket.getInputStream();
			
			int dataSize = 0;
			System.out.println("Data Size: " + dataSize);
			
			//Creating syn packet-----------------------------------------------------------
			byte[] ipv4Header = generateIpv4(generateTcp(generateRandomData(2)));
			
			out.write(ipv4Header);
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
	    short fillerPort =0x420;
	    int sequenceNum = 3232;
	    byte dataOffset = 5;
	    byte reserved = 0;
	    byte flagsTCP = 0b00000010;
	    short windowSize = 0;
	    short urgentPointer = 0;
		

		//------Begin PseudoHeaderTCP-----------------------------------------------------------
		//short pseudoHlen = 8;
		//byte[] pHeader = new byte[(pseudoHlen * 4) + data.length];
		byte[] pHeader = new byte[12 + 20];
		ByteBuffer pHeaderBuf = ByteBuffer.wrap(pHeader);
		pHeaderBuf.putShort(fillerPort);
		pHeaderBuf.putShort(fillerPort);
		pHeaderBuf.putInt(sequenceNum);
		pHeaderBuf.putInt(0);
		pHeaderBuf.put((byte) ((dataOffset & 0xF) << 4 | reserved & 0xF) );
		pHeaderBuf.put((byte) flagsTCP);
		pHeaderBuf.putShort(windowSize);
		pHeaderBuf.putShort((short) 0);
		pHeaderBuf.putShort(urgentPointer);


		int tcpHlen = 20 ;
		byte[] header = new byte[tcpHlen];
		ByteBuffer headerBuf = ByteBuffer.wrap(header);
		headerBuf.putShort((short)fillerPort);//Random Source Port
		headerBuf.putShort((short)fillerPort); //Random Dest Port
		headerBuf.putInt(sequenceNum);   //Random sequence number
		headerBuf.putInt(0); // Acknowledgment number (if ACK set)
		headerBuf.put((byte) ((dataOffset & 0xF) << 4 | reserved & 0xF) ); //NS flag = 0(Built in reserve)	
		//Flags --> [cwr,ece,urg,ack,psh,rst,syn,fin] *Note: not including NS flag. Look above^^
		headerBuf.put((byte) flagsTCP);
		headerBuf.putShort(windowSize);
		headerBuf.putShort((checksum_Funct_TCP(pHeaderBuf,(byte) 5)));
		headerBuf.putShort(urgentPointer);
		//pHeaderBuf.put(data);
		//System.out.println("pHeaderBuf.capacity()/4: " + pHeaderBuf.capacity()/4.0);
		//System.out.println("Right before checksum_Funct_TCP Checkpoint");	
		//checksum = checksum_Funct2(pHeaderBuf,(byte) hlen);
		//------End PseudoHeaderTCP-------------------------------------------------------------
		//headerBuf.put(data);
		//System.out.println("Done generateTCP Checkpoint");
		return header;
	}// end Function generateTcp
	
	public static short checksum_Funct(ByteBuffer bb, byte hlen){
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
	
    public static short checksum_Funct_TCP(ByteBuffer header,int hlen){
    	 int sum = 0;
    	 header.rewind();
    	 //sum pseudo header
		 sum += ((srcAddress >> 16) & 0xFFFF) + (srcAddress & 0xFFFF);
		 sum += ((destAddress >> 16) & 0xFFFF) + (destAddress & 0xFFFF);
		 sum += (byte) protocol & 0xFFFF;
		 sum += (short)(20) & 0xFFFF;
		 
		 //Sum tcp segment
		 for (int i = 0; i < hlen*2 ; i++){
		   sum += 0xFFFF & header.getShort();
		 }    
		 // if length is odd
		 if(hlen % 2 > 0){
		   sum += (header.get() & 0xFF) << 8;
		 }
		 sum = ((sum >> 16) & 0xFFFF) + (sum & 0xFFFF);
		 short result = (short) (~sum & 0xFFFF);
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
