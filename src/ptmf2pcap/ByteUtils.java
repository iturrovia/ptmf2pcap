package ptmf2pcap;
import java.util.ArrayList;

/*
 * This class provides the tools that ptmf2pcap application needs to deal with byte arrays and translate them
 * from/to numeric values and hexadecimal strings
 */
public class ByteUtils {

	private static final String HEX_CHARS = "0123456789ABCDEF";
	
	/**
	 * Creates a subarray
	 *
	 * @param	bytes		the input byte array
	 * @param	startIndex	the start index
	 * @param	length		the length of the output subarray
	 * @return	the subarray
	 */
	public static byte[] subarray(byte[] inputBytes, int startIndex, int length) {
		byte[] outputBytes = new byte[length];
		System.arraycopy(inputBytes, startIndex, outputBytes, 0, length);
		return outputBytes;
	};
	
	/**
	 * Joins all the byte arrays from an input ArrayList
	 *
	 * @param	bytesArrayList	a ArrayList containing byte arrays 
	 * @return	a byte array containing the concatenation of all the byte arrays from the input ArrayList
	 */
	public static byte[] join(ArrayList<byte[]> bytesArrayList) {
		byte[] bytes;
		int outputLength = 0;
		for(int i = 0; i < bytesArrayList.size(); i++) {
			bytes = bytesArrayList.get(i);
			outputLength = outputLength + bytes.length;
		}
		byte[] outputByteArray = new byte[outputLength];
		outputLength = 0;
		for(int i = 0; i < bytesArrayList.size(); i++) {
			bytes = bytesArrayList.get(i);
			System.arraycopy(bytes, 0, outputByteArray, outputLength, bytes.length);
			outputLength = outputLength + bytes.length;
		}
		return outputByteArray;
	};
	
	/**
	 * Checks if a byte array matches a pattern at a specific offset
	 *
	 * @param	bytes	a byte array
	 * @param	offset	the offset at which the pattern will be evaluated
	 * @param	pattern	the pattern to match
	 * @return	whether the match was or not successfull
	 */
	public static boolean matchPattern(byte[] bytes, int offset, byte[] pattern) {
		boolean result;
		if((bytes.length - offset) >= pattern.length) {
			result = true;
			for(int i=0; i < pattern.length; i++) {
				if(pattern[i] != bytes[offset + i]) {
					result = false;
					break;
				}
			}
		} else {
			result = false;
		}
		return result;
	}
	
	/**
	 * Splits the byte array
	 *
	 * @param	bytes		a byte array 
	 * @param	separator	the separator 
	 * @return	an ArrayList of byte arrays resulting of splitting the original one
	 */
	public static ArrayList<byte[]> split(byte[] bytes, byte[] separator) {
		ArrayList<byte[]> bytesArrayList = new ArrayList<byte[]>();
		ArrayList<Integer> indexArrayList = new ArrayList<Integer>();
		int subarrayStartIndex;
		int subarrayLength;
		for(int i = 0; i < (bytes.length - separator.length); i++) {
			if(matchPattern(bytes, i, separator)) {
				indexArrayList.add(new Integer(i));
			}
		}
		if(indexArrayList.size() > 0) {
			// First we check if there is a subarray before first match
			if(indexArrayList.get(0).intValue() > 0) {
				subarrayStartIndex = 0;
				subarrayLength = indexArrayList.get(0).intValue();
				bytesArrayList.add(subarray(bytes, subarrayStartIndex, subarrayLength));
			};
			// Now we process the subarrays between matches
			for(int i=0; i < (indexArrayList.size() - 1); i++) {
				subarrayStartIndex = indexArrayList.get(i).intValue() + separator.length;
				subarrayLength = indexArrayList.get(i + 1).intValue() - subarrayStartIndex;
				bytesArrayList.add(subarray(bytes, subarrayStartIndex, subarrayLength));
			}
			// Now with possible subarray after last match
			subarrayStartIndex = indexArrayList.get(indexArrayList.size() - 1).intValue() + separator.length;
			subarrayLength = bytes.length - subarrayStartIndex;
			if(subarrayLength > 0) {
				bytesArrayList.add(subarray(bytes, subarrayStartIndex, subarrayLength));
			}
		} else {
			// No match, therefore the only subsarray is the whole content
			bytesArrayList.add(bytes);
		}
		return bytesArrayList;
	};
	
	/**
	 * Converts an hexadecimal string to a byte array
	 *
	 * @param	hexString	the hexadecimal string
	 * @return				the byte array
	 */
	public static byte[] hexStringToByteArray(String hexString) {
		byte[] bytes = new byte[hexString.length() / 2];
		for (int i = 0; i < bytes.length; i++) {
			int index = i * 2;
			int byteIntValue = Integer.parseInt(hexString.substring(index, index + 2), 16);
			bytes[i] = (byte) byteIntValue;
		}
		return bytes;
	}
	
	/**
	 * Converts a byte array to an hexadecimal string
	 *
	 * @param	bytes	the hexadecimal string
	 * @return	the hexadecimal string
	 */
	public static String bytesToHexString(byte [] bytes) {
		String hexString = null;
		StringBuilder hexStringBuilder = null;
		if(bytes != null) {
			hexStringBuilder = new StringBuilder(2 * bytes.length);
			for(byte b : bytes) {
				hexStringBuilder.append(HEX_CHARS.charAt((b & 0xF0) >> 4)).append(HEX_CHARS.charAt((b & 0x0F)));
			}
		}
		return hexStringBuilder.toString();
	};
	
	/**
	 * Reverses the endianness of an hexadecimal string
	 *
	 * @param	hexString	the input hexadecimal string
	 * @return				the endiannessly-reversed hexadecimal string
	 */
	public static String reverseEndian(String hexString) {
		String reversedHexString = "";
		for(int index = 0; index < hexString.length()/2; index++) {
			reversedHexString = reversedHexString + hexString.substring(hexString.length() - (2 * (index + 1)), hexString.length() - (2 * index));
		};
		return reversedHexString;
	};
	
	/**
	 * Converts an integer value to an hexadecimal string
	 *
	 * @param	intValue		the integer value to convert to hexadecimal string
	 * @param	hexStringLength	the length of the ouput hexadecimal string
	 * @return					the output hexadecimal string
	 */
	public static String intToHexString(int intValue, int hexStringLength) {
		String hexString = Integer.toHexString(intValue);
		while(hexString.length() < hexStringLength) {
			hexString = "0" + hexString;
		};
		return hexString;
	};
	
	/**
	 * Converts a long value to an hexadecimal string
	 *
	 * @param	longValue		the long value to convert to hexadecimal string
	 * @param	hexStringLength	the length of the ouput hexadecimal string
	 * @return					the output hexadecimal string
	 */
	public static String longToHexString(long longValue, int hexStringLength) {
		String hexString = Long.toHexString(longValue);
		while(hexString.length() < hexStringLength) {
			hexString = "0" + hexString;
		};
		return hexString;
	};
	
	/**
	 * Converts an integer value to a byte array
	 *
	 * @param	intValue		the integer value to convert to byte array
	 * @param	byteArrayLength	the length of the ouput byte array
	 * @param	isLittleEndian	whether the output byte array must be filled in little endian format
	 * @return					the output byte array
	 */
	public static byte[] intToByteArray(int intValue, int byteArrayLength, boolean isLittleEndian) {
		byte[] bytes;
		String hexString = intToHexString(intValue, 2 * byteArrayLength);
		if(isLittleEndian) {
			hexString = reverseEndian(hexString);
		};
		bytes = hexStringToByteArray(hexString);;
		return bytes;
	};
	
	/**
	 * Converts a long value to a byte array
	 *
	 * @param	longValue		the long value to convert to byte array
	 * @param	byteArrayLength	the length of the ouput byte array
	 * @param	isLittleEndian	whether the output byte array must be filled in little endian format
	 * @return					the output byte array
	 */
	public static byte[] longToByteArray(long longValue, int byteArrayLength, boolean littleEndian) {
		byte[] bytes;
		String hexString = longToHexString(longValue, 2 * byteArrayLength);
		if(littleEndian) {
			hexString = reverseEndian(hexString);
		};
		bytes = hexStringToByteArray(hexString);;
		return bytes;
	};
	
	/**
	 * Converts an hex string to an ASCII string
	 *
	 * @param	ch	the hexadecimal character
	 * @return		the corresponding int value
	 */
	public static String hexToAsciiString(String hexString) {
		int hexStringLength = hexString.length();
		StringBuilder sb = new StringBuilder(hexStringLength / 2);
		for (int i = 0; i < hexStringLength; i += 2) {
			sb.append((char) Integer.parseInt("0" + hexString.substring(i, i + 2), 16) );
		}
		return sb.toString();
	}
	
	/**
	 * Converts a byte array to an ASCII string
	 *
	 * @param	bytes	the byte array
	 * @return			the corresponding ASCII string
	 */
	public static String bytesToAsciiString(byte[] bytes) {
		return hexToAsciiString(bytesToHexString(bytes));
	}

}