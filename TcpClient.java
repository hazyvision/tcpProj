//Adriene Cuenco
//Initial branch

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
    /*
    static OutputStream out;
    static InputStream in;
    */
    
	public static void main(String[] args) {
		try(Socket socket = new Socket("76.91.123.97", 38006)){
			OutputStream out = socket.getOutputStream();
			InputStream in = socket.getInputStream();
			
			int dataSize = 2;
			//Creating syn packet-----------------------------------------------------------
			byte[] data = generateRandomData(dataSize); 
			byte[] tcpHeader = generateTcp(data);
			byte[] ipv4Header = generateIpv4(tcpHeader);
			
			out.write(ipv4Header);
			
			byte[] synPacket = new byte[4];
			in.read(synPacket);
			//ByteBuffer synPacketBuf = ByteBuffer.wrap(synPacket);
			System.out.println("synPacket> " +  DatatypeConverter.printHexBinary(synPacket));
			//SYN packet complete------------------------------------------------------------
				
		}
		catch(Exception e){
			System.out.println("Incorrect address or port number.");
			System.out.println("Socket is closing...");
		}
	} // End Main
	
	public static byte[] generateIpv4(byte[] data){
		byte[] header = new byte[20 + data.length];
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
		byte[] header = new byte[20 + data.length];
		ByteBuffer headerBuf = ByteBuffer.wrap(header);
		checksum = 0;
		
		int sequenceNum = 3232;
		byte dataOffset = 5;
		byte reserved = 0;
		short windowSize = 0;
		short urgentPointer = 0;
		
		headerBuf.putShort((short)0x420);//Random Source Port
		headerBuf.putShort((short)0x013); //Random Dest Port
		headerBuf.putInt(sequenceNum);   //Random sequence number
		headerBuf.putInt(sequenceNum + 1); // Acknowledgment number (if ACK set)
		headerBuf.put((byte) ((dataOffset & 0xF) << 4 | reserved & 0xF) ); //NS flag = 0(Built in reserve)
		
		//Flags --> [cwr,ece,urg,ack,psh,rst,syn,fin]
		headerBuf.put((byte) 0b00000010);
		headerBuf.putShort(windowSize);
		headerBuf.putShort(checksum);
		headerBuf.putShort(urgentPointer);
		checksum_Funct(headerBuf,hlen);
		headerBuf.put(data);
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
	
	public static byte[] generateRandomData(int size){
		Random r = new Random();
		byte[] randomArr = new byte[size];
		for (int i = 0; i < size; i++){
			randomArr[i] = (byte)r.nextInt();
		}
		return randomArr;
	} // end Function generateRandomData
	
	

} // End Class TcpClient
