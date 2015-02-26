
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
    static int ack;
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
    
    static int sequenceNum = 7;
    
	public static void main(String[] args) throws Exception {
		try(Socket socket = new Socket("45.50.5.238", 38006)){
			System.out.println("Connected to server successfully...");
			System.out.println(socket);
			System.out.println("------------------------------------------------------");
			
			OutputStream out = socket.getOutputStream();
			InputStream in = socket.getInputStream();
			
			//Creating syn packet
			System.out.println("***Handshake***");
			byte[] ipv4Header = generateIpv4(generateTcp_syn(false));	
			out.write(ipv4Header);
			byte[] synPacket = new byte[4];
			in.read(synPacket);
			System.out.println("synPacket> " +  DatatypeConverter.printHexBinary(synPacket));
			//SYN packet complete
			
			//Tcp header From server--ACK packet
			sequenceNum++;
			byte[] serverResponse1 = new byte[20];
			in.read(serverResponse1);		
			byte[] value = {serverResponse1[4], serverResponse1[5], serverResponse1[6], serverResponse1[7]};
			ByteBuffer n = ByteBuffer.wrap(value);
			int result = n.getInt() + 1;
			ack = result;

			byte[] nextIpv4Header = generateIpv4(generateTcp_ack());			
			out.write(nextIpv4Header);			
			byte[] ackPacket = new byte[4];
			in.read(ackPacket);
			System.out.println("ackPacket> " +  DatatypeConverter.printHexBinary(ackPacket));
			
			// ACk packet complete
			System.out.println("------------------------------------------------------");
			System.out.println("***Data Packets***");
			//Begin Packets with data
			int size = 2;
			int incrSeq = 1;	
			for(int i = 1; i <= 12; i++){
				sequenceNum += incrSeq;
				ack++;
				//System.out.println(size + " " + sequenceNum + " " + ack);
				byte[] packet = generateIpv4(generateTcp_Packet(generateRandomData(size)));
				out.write(packet);
				byte [] accept = new byte[4];
				in.read(accept);
				System.out.println("Packet #"+ i +"> "+DatatypeConverter.printHexBinary(accept));
				incrSeq+= incrSeq;
				size+=size;			
			}//End for loop_12 packets with data	
			System.out.println("------------------------------------------------------");
			System.out.println("***Teardown***");
			//Begin Teardown
			
			//finPacket
			byte[] initialTeardown = generateIpv4(generateTcp_syn(true));
			out.write(initialTeardown);
			byte[] teardownResponse = new byte[4];
			in.read(teardownResponse);
			System.out.println("finPacket> " +  DatatypeConverter.printHexBinary(teardownResponse));
			//End finPacket		
			System.out.println();
			
			//Receive ack response from server
			byte[] tearDownInitialResponse = new byte[20];
			in.read(tearDownInitialResponse);
			System.out.println("Recieving TCP packet with ack flag...");
			System.out.println("server> 0x"+ DatatypeConverter.printHexBinary(tearDownInitialResponse));
			System.out.println();
			
			//Receive fin response from server
			byte[] tearDownSecondResponse = new byte[20];
			in.read(tearDownSecondResponse);
			System.out.println("Recieving TCP packet with fin flag...");
			System.out.println("server> 0x"+ DatatypeConverter.printHexBinary(tearDownSecondResponse));
			System.out.println();
			
			//Send final ackPacket
			byte[] finalTeardown = generateIpv4(generateTcp_ack());
			out.write(finalTeardown);
			byte[] teardownFinalResponse = new byte[4];
			in.read(teardownFinalResponse);
			System.out.println("FinalResponse> " +  DatatypeConverter.printHexBinary(teardownFinalResponse));
			//End Teardown
			
			System.out.println();
			System.out.println("TCP connection establishment and connection teardown complete.");
			System.out.println("Program terminating...");
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
	
	public static byte[] generateTcp_syn(boolean isTeardown){	
		byte flagsTCP;
		//Check if packet is a handshake or a Teardown
		if(isTeardown) flagsTCP = 0b00000001; //fin flag on 	
		else flagsTCP = 0b00000010; //syn flag on
		
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

		byte[] header = new byte[tcpHlen];
		ByteBuffer headerBuf = ByteBuffer.wrap(header);
		headerBuf.putShort((short)fillerPort);//Random Source Port
		headerBuf.putShort((short)fillerPort); //Random Dest Port
		headerBuf.putInt(sequenceNum);   //sequence number
		headerBuf.putInt(0); // Acknowledgment number (if ACK set)
		headerBuf.put((byte) ((dataOffset & 0xF) << 4 | reserved & 0xF) ); //NS flag = 0(Built in reserve)	
		//Flags --> [cwr,ece,urg,ack,psh,rst,syn,fin] *Note: not including NS flag. Look above^^
		
		headerBuf.put(flagsTCP);
		headerBuf.putShort(windowSize);
		headerBuf.putShort((checksum_Funct_TCP(pHeaderBuf,header.length)));
		headerBuf.putShort(urgentPointer);
		return header;
	}// end Function generateTcp_syn
	
	public static byte[] generateTcp_ack(){
	    byte flagsTCP = 0b00010010;
		//------Begin PseudoHeaderTCP-----------------------------------------------------------
		byte[] pHeader = new byte[12 + 20];
		ByteBuffer pHeaderBuf = ByteBuffer.wrap(pHeader);
		pHeaderBuf.putShort(fillerPort);
		pHeaderBuf.putShort(fillerPort);
		pHeaderBuf.putInt(sequenceNum);
		pHeaderBuf.putInt(ack);
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
		headerBuf.putInt(sequenceNum);   //sequence number
		headerBuf.putInt(ack);
		headerBuf.put((byte) ((dataOffset & 0xF) << 4 | reserved & 0xF) ); //NS flag = 0(Built in reserve)	
		//Flags --> [cwr,ece,urg,ack,psh,rst,syn,fin] *Note: not including NS flag. Look above^^
		headerBuf.put((byte) flagsTCP);
		headerBuf.putShort(windowSize);
		headerBuf.putShort((checksum_Funct_TCP(pHeaderBuf,header.length)));
		headerBuf.putShort(urgentPointer);
		return header;
	}//end function generateTcp_ack
	
	public static byte[] generateTcp_Packet(byte [] data){
	    byte flagsTCP = 0b00010010;
		//------Begin PseudoHeaderTCP-----------------------------------------------------------
		byte[] pHeader = new byte[12 + 20 + data.length];
		ByteBuffer pHeaderBuf = ByteBuffer.wrap(pHeader);
		pHeaderBuf.putShort(fillerPort);
		pHeaderBuf.putShort(fillerPort);
		pHeaderBuf.putInt(sequenceNum);
		pHeaderBuf.putInt(ack);
		pHeaderBuf.put((byte) ((dataOffset & 0xF) << 4 | reserved & 0xF) );
		pHeaderBuf.put(flagsTCP);
		pHeaderBuf.putShort(windowSize);
		pHeaderBuf.putShort((short) 0);
		pHeaderBuf.putShort(urgentPointer);
		//------End PseudoHeaderTCP-------------------------------------------------------------
		byte[] header = new byte[tcpHlen + data.length];
		ByteBuffer headerBuf = ByteBuffer.wrap(header);
		headerBuf.putShort((short)fillerPort);//Random Source Port
		headerBuf.putShort((short)fillerPort); //Random Dest Port
		headerBuf.putInt(sequenceNum);   //sequence number
		headerBuf.putInt(ack);
		headerBuf.put((byte) ((dataOffset & 0xF) << 4 | reserved & 0xF) ); //NS flag = 0(Built in reserve)	
		//Flags --> [cwr,ece,urg,ack,psh,rst,syn,fin] *Note: not including NS flag. Look above^^
		headerBuf.put((byte) flagsTCP);
		headerBuf.putShort(windowSize);
		headerBuf.putShort((checksum_Funct_TCP(pHeaderBuf, header.length)));
		headerBuf.putShort(urgentPointer);
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
	
    public static short checksum_Funct_TCP(ByteBuffer header,int length){
    	 int sum = 0;
    	 header.rewind();
    	 //sum pseudo header
		 sum += ((srcAddress >> 16) & 0xFFFF) + (srcAddress & 0xFFFF);
		 sum += ((destAddress >> 16) & 0xFFFF) + (destAddress & 0xFFFF);
		 sum += (byte) protocol & 0xFFFF;
		 sum += length & 0xFFFF;
		 
		 //Sum tcp segment
		 for (int i = 0; i < length/2 ; i++){
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
