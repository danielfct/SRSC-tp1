package utils;

import java.io.File;
import java.io.StringReader;

import javax.crypto.spec.PBEKeySpec;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.w3c.dom.Document;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;
import org.w3c.dom.Node;
import org.w3c.dom.Element;

public class XmlParser {

	public static String getUserProperty(PBEKeySpec pbeKeySpec, String multicastIp, String userId, String property) throws Exception {
		Element user = XmlParser.getUserProperties(pbeKeySpec, multicastIp, userId);
		if (user != null) {
			NodeList properties = user.getElementsByTagName(property);
			if (properties.getLength() < 1) {
				return null;
			}
			Node n = properties.item(0);
			if (n == null) {
				return null;
			}
			return n.getTextContent();
		}
		return null;
	}
	
	public static Element getUserProperties(PBEKeySpec pbeKeySpec, String multicastIp, String userId) throws Exception {
		String file = Utils.decryptFile(pbeKeySpec, "res/users.axx");
		DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
	    DocumentBuilder builder = factory.newDocumentBuilder();
	    InputSource is = new InputSource(new StringReader(file));
		Document doc = builder.parse(is);
		doc.getDocumentElement().normalize();
		NodeList rooms = doc.getElementsByTagName("room");
		for (int i = 0; i < rooms.getLength(); i++) {
			Node rNode = rooms.item(i);
			if (rNode.getNodeType() == Node.ELEMENT_NODE) {
				Element room = (Element) rNode;
				String ip = room.getAttribute("ip");
				if (multicastIp.equals(ip)) {
					NodeList users = room.getChildNodes();
					for (int j = 0; j < users.getLength(); j++) {
						Node uNode = users.item(j);
						if (uNode.getNodeType() == Node.ELEMENT_NODE) {
							Element user = (Element) uNode;
							String id = user.getAttribute("id");
							if (userId.equals(id)) {
								return user;
							}
						}
					}
				}
			}
		}
		return null;
	}

	public static String getRoomProperty(String multicastIp, String property) throws Exception {
		File inputFile = new File("res/ciphersuite.conf");
        Document doc = DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(inputFile);
		doc.getDocumentElement().normalize();
		NodeList rooms = doc.getElementsByTagName("room");
		for (int i = 0; i < rooms.getLength(); i++) {
			Node rNode = rooms.item(i);
			if (rNode.getNodeType() == Node.ELEMENT_NODE) {
				Element room = (Element) rNode;
				String ip = room.getAttribute("ip");
				if (multicastIp.equals(ip)) {
					NodeList properties = room.getElementsByTagName(property);
					if (properties.getLength() < 1) {
						return null;
					}
					Node n = properties.item(0);
					if (n == null) {
						return null;
					}
					return n.getTextContent();
				}
			}
		}
		return null;
	}
}
