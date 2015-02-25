
//Adriene Cuenco


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
    //static int destAddress = 0x2D325EE; //45.50.5.238
    
    static byte dataOffset = 5;
    static byte reserved = 0;
    static short windowSize = 0;
    static short urgentPointer = 0;
    static int tcpHlen = 20 ;
    static short fillerPort = 0x420;
    
    static int sequenceNum = 0;
    
	public static void main(String[] args) throws UnknownHostException {
		try(Socket socket = new Socket("45.50.5.238", 38006)){
			System.out.println("Connected to server successfully...");
			System.out.println(socket);
			System.out.println("------------------------------------------------------");
			
			OutputStream out = socket.getOutputStream();
			InputStream in = socket.getInputStream();
			
			//Creating syn packet
			byte[] ipv4Header = generateIpv4(generateTcp_syn());	
			out.write(ipv4Header);
			byte[] synPacket = new byte[4];
			in.read(synPacket);
			System.out.println("synPacket> " +  DatatypeConverter.printHexBinary(synPacket));
			//SYN packet complete
			
			//Tcp header From server--ACK packet
			sequenceNum++;
			byte[] serverResponse1 = new byte[20];
			in.read(serverResponse1);		
			short[] tcpTemp = byteToShort(serverResponse1);		
			short[] seqNumFromServerResponse1 = new short[2];
			seqNumFromServerResponse1[0] = tcpTemp[2];
			seqNumFromServerResponse1[1] = tcpTemp[3];			
			byte[] nextIpv4Header = generateIpv4(generateTcp_ack(seqNumFromServerResponse1));			
			out.write(nextIpv4Header);			
			byte[] ackPacket = new byte[4];
			in.read(ackPacket);
			System.out.println("ackPacket> " +  DatatypeConverter.printHexBinary(ackPacket));
			// ACk packet complete
			System.out.println("------------------------------------------------------");
			
			int dataSize = 2;
			//sequenceNum++;
			for(int i = 1; i <= 12; i++){		
				sequenceNum+=dataSize;
				byte[] packet = generateIpv4(generateTcp_packet(generateRandomData(dataSize)));
				out.write(packet);
				byte[] response = new byte[4];
				in.read(response);
				System.out.println("Packet #" + i + "> " + DatatypeConverter.printHexBinary(response));
				dataSize*=2;
				
			}//End for_12 packets complete
					
	
			System.out.println("Reached end of code.");
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
	
	public static byte[] generateTcp_syn(){		
	    byte flagsTCP = 0b00000010;
		//------Begin PseudoHeaderTCP-----------------------------------------------------------
		byte[] pHeader = new byte[12 + 20];
		ByteBuffer pHeaderBuf = ByteBuffer.wrap(pHeader);
		pHeaderBuf.putShort(fillerPort);
		pHeaderBuf.putShort(fillerPort);
		pHeaderBuf.putInt(sequenceNum);
		pHeaderBuf.putInt(0);
		pHeaderBuf.put((byte) ((dataOffset & 0xF) << 4 | reserved & 0xF) );
		pHeaderBuf.put(flagsTCP);
		pHeaderBuf.putShort(windowSize);
		pHeaderBuf.putShort((short) 0);
		pHeaderBuf.putShort(urgentPointer);
		//------End PseudoHeaderTCP-------------------------------------------------------------

		int tcpHlen = 20 ;
		byte[] header = new byte[tcpHlen];
		ByteBuffer headerBuf = ByteBuffer.wrap(header);
		headerBuf.putShort((short)fillerPort);//Random Source Port
		headerBuf.putShort((short)fillerPort); //Random Dest Port
		headerBuf.putInt(sequenceNum);   //Random sequence number
		headerBuf.putInt(0); // Acknowledgment number (if ACK set)
		headerBuf.put((byte) ((dataOffset & 0xF) << 4 | reserved & 0xF) ); //NS flag = 0(Built in reserve)	
		//Flags --> [cwr,ece,urg,ack,psh,rst,syn,fin] *Note: not including NS flag. Look above^^
		
		headerBuf.put(flagsTCP);
		headerBuf.putShort(windowSize);
		headerBuf.putShort((checksum_Funct_TCP(pHeaderBuf,(byte) 5)));
		headerBuf.putShort(urgentPointer);
		return header;
	}// end Function generateTcp_syn
	
	public static byte[] generateTcp_ack(short[] fromServer){
	    byte flagsTCP = 0b00010010;
		//------Begin PseudoHeaderTCP-----------------------------------------------------------
		byte[] pHeader = new byte[12 + 20];
		ByteBuffer pHeaderBuf = ByteBuffer.wrap(pHeader);
		pHeaderBuf.putShort(fillerPort);
		pHeaderBuf.putShort(fillerPort);
		pHeaderBuf.putInt(sequenceNum);
		pHeaderBuf.putShort(fromServer[0]); // Acknowledgment number from server
		pHeaderBuf.putShort((short) (fromServer[1] + 1)); // Acknowledgment number from server
		pHeaderBuf.put((byte) ((dataOffset & 0xF) << 4 | reserved & 0xF) );
		pHeaderBuf.put(flagsTCP);
		pHeaderBuf.putShort(windowSize);
		pHeaderBuf.putShort((short) 0);
		pHeaderBuf.putShort(urgentPointer);
		//------End PseudoHeaderTCP-------------------------------------------------------------
		byte[] header = new byte[tcpHlen];
		ByteBuffer headerBuf = ByteBuffer.wrap(header);
		headerBuf.putShort((short)fillerPort);//Random Source Port
		headerBuf.putShort((short)fillerPort); //Random Dest Port
		headerBuf.putInt(sequenceNum);   //Random sequence number
		headerBuf.putShort(fromServer[0]); // Acknowledgment number from server
		headerBuf.putShort((short) (fromServer[1] + 1)); // Acknowledgment number from server
		headerBuf.put((byte) ((dataOffset & 0xF) << 4 | reserved & 0xF) ); //NS flag = 0(Built in reserve)	
		//Flags --> [cwr,ece,urg,ack,psh,rst,syn,fin] *Note: not including NS flag. Look above^^
		headerBuf.put((byte) flagsTCP);
		headerBuf.putShort(windowSize);
		headerBuf.putShort((checksum_Funct_TCP(pHeaderBuf,(byte) 5)));
		headerBuf.putShort(urgentPointer);
		return header;
	}//end function generateTcp_ack
	
	public static byte[] generateTcp_packet(byte[] data){		
	    byte flagsTCP = 0b00000000;
		//------Begin PseudoHeaderTCP-----------------------------------------------------------
		byte[] pHeader = new byte[12 + tcpHlen + data.length];
		ByteBuffer pHeaderBuf = ByteBuffer.wrap(pHeader);
		pHeaderBuf.putShort(fillerPort);
		pHeaderBuf.putShort(fillerPort);
		pHeaderBuf.putInt(sequenceNum);
		pHeaderBuf.putInt(0); 
		pHeaderBuf.put((byte) ((dataOffset & 0xF) << 4 | reserved & 0xF) );
		pHeaderBuf.put(flagsTCP);
		pHeaderBuf.putShort(windowSize);
		pHeaderBuf.putShort((short) 0);
		pHeaderBuf.putShort(urgentPointer);
		pHeaderBuf.put(data);
		//------End PseudoHeaderTCP-------------------------------------------------------------
		
		byte[] header = new byte[tcpHlen + data.length];
		ByteBuffer headerBuf = ByteBuffer.wrap(header);
		headerBuf.putShort((short)fillerPort);//Random Source Port
		headerBuf.putShort((short)fillerPort); //Random Dest Port
		headerBuf.putInt(sequenceNum);  
		headerBuf.putInt(0); // Acknowledgment number from server
		headerBuf.put((byte) ((dataOffset & 0xF) << 4 | reserved & 0xF) ); //NS flag = 0(Built in reserve)	
		//Flags --> [cwr,ece,urg,ack,psh,rst,syn,fin] *Note: not including NS flag. Look above^^
		headerBuf.put((byte) flagsTCP);
		headerBuf.putShort(windowSize);
		headerBuf.putShort((checksum_Funct_TCP(pHeaderBuf,(byte) 5)));
		headerBuf.putShort(urgentPointer);
		headerBuf.put(data);
		return header;
	}//end function generateTcp_ack
	
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
	
	private static short[] byteToShort(byte[] toShort) {
	    short[] result = new short[(toShort.length + 1) /2];
	    for (int i = 0, j = 0; j < toShort.length - 1; i++, j+=2) {
	            result[i] |= (toShort[j] & 0xFF);
	            result[i] <<= 8;
	            result[i] |= (toShort[j + 1] & 0xFF);
	    }
	    return result;
    }
	public static byte[] generateRandomData(int size){
		Random r = new Random();
		byte[] randomArr = new byte[size];
		for (int i = 0; i < size; i++){
			randomArr[i] = (byte)r.nextInt();
		}
		return randomArr;
	} // end Function generateRandomData

	

} // End Class TcpClient
