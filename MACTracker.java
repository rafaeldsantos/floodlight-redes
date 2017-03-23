package net.floodlightcontroller.mactracker;

import org.projectfloodlight.openflow.protocol.match.Match;
import org.projectfloodlight.openflow.protocol.match.MatchField;
import java.util.Collection;
import java.util.Map;

import org.projectfloodlight.openflow.protocol.OFFlowMod;
import org.projectfloodlight.openflow.protocol.OFMessage;
import org.projectfloodlight.openflow.protocol.OFType;
import org.projectfloodlight.openflow.protocol.action.OFAction;
import org.projectfloodlight.openflow.protocol.action.OFActionOutput;
import org.projectfloodlight.openflow.protocol.match.Match.Builder;
import org.projectfloodlight.openflow.protocol.match.MatchField;
import org.projectfloodlight.openflow.types.EthType;
import org.projectfloodlight.openflow.types.IPv4Address;
import org.projectfloodlight.openflow.types.IPv4AddressWithMask;
import org.projectfloodlight.openflow.types.IpProtocol;
import org.projectfloodlight.openflow.types.MacAddress;
import org.projectfloodlight.openflow.types.OFBufferId;
import org.projectfloodlight.openflow.types.OFPort;
import org.projectfloodlight.openflow.types.TransportPort;
import org.projectfloodlight.openflow.types.VlanVid;

import net.floodlightcontroller.core.FloodlightContext;
import net.floodlightcontroller.core.IOFMessageListener;
import net.floodlightcontroller.core.IOFSwitch;
import net.floodlightcontroller.core.module.FloodlightModuleContext;
import net.floodlightcontroller.core.module.FloodlightModuleException;
import net.floodlightcontroller.core.module.IFloodlightModule;
import net.floodlightcontroller.core.module.IFloodlightService;

import net.floodlightcontroller.core.IFloodlightProviderService;
import java.util.ArrayList;
import java.util.concurrent.ConcurrentSkipListSet;
import java.util.Set;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentSkipListSet;

import net.floodlightcontroller.packet.ARP;
import net.floodlightcontroller.packet.Ethernet;
import net.floodlightcontroller.packet.IPv4;
import net.floodlightcontroller.packet.TCP;
import net.floodlightcontroller.packet.UDP;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class MACTracker implements IOFMessageListener, IFloodlightModule {

	protected IFloodlightProviderService floodlightProvider;
	protected Set<Long> macAddresses;
	protected static Logger logger;
	
	//Criados pelo usuario.------------------
	final private String Switch1 = "00:00:00:00:00:00:00:01";
	final private String Switch2 = "00:00:00:00:00:00:00:02";
	final private String Switch3 = "00:00:00:00:00:00:00:03";
	final private String Switch4 = "00:00:00:00:00:00:00:04";

	final private String IpH1 = "/10.0.0.5";
	final private String IpH2 = "/10.0.0.6";
	
	final private OFPort Port_S1_H1 = OFPort.of(1);
	final private OFPort Port_S1_S2 = OFPort.of(2);
	final private OFPort Port_S1_S3 = OFPort.of(3);
	final private OFPort Port_S2_S1 = OFPort.of(1);
	final private OFPort Port_S2_S4 = OFPort.of(2);
	final private OFPort Port_S3_S1 = OFPort.of(1);
	final private OFPort Port_S3_S4 = OFPort.of(2);
	final private OFPort Port_S4_H2 = OFPort.of(1);
	final private OFPort Port_S4_S2 = OFPort.of(2);	
	final private OFPort Port_S4_S3 = OFPort.of(3);
	//---------------------------------------

	@Override
	public String getName() {
		return MACTracker.class.getSimpleName();
	}

	@Override
	public boolean isCallbackOrderingPrereq(OFType type, String name) {
		return false;
	}

	@Override
	public boolean isCallbackOrderingPostreq(OFType type, String name) {
		return false;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleServices() {
		return null;
	}

	@Override
	public Map<Class<? extends IFloodlightService>, IFloodlightService> getServiceImpls() {
		return null;
	}

	@Override
	public Collection<Class<? extends IFloodlightService>> getModuleDependencies() {
		Collection<Class<? extends IFloodlightService>> l = new ArrayList<Class<? extends IFloodlightService>>();
		l.add(IFloodlightProviderService.class);
		return l;
	}

	@Override
	public void init(FloodlightModuleContext context) throws FloodlightModuleException {
		floodlightProvider = context.getServiceImpl(IFloodlightProviderService.class);
		macAddresses = new ConcurrentSkipListSet<Long>();
		logger = LoggerFactory.getLogger(MACTracker.class);
	}

	@Override
	public void startUp(FloodlightModuleContext context) {
		floodlightProvider.addOFMessageListener(OFType.PACKET_IN, this);
	}

	@Override
	public net.floodlightcontroller.core.IListener.Command receive(IOFSwitch sw, OFMessage msg, FloodlightContext cntx) {
		Ethernet eth = IFloodlightProviderService.bcStore.get(cntx, IFloodlightProviderService.CONTEXT_PI_PAYLOAD); //Obtem os dados do pacote ethernet.
		OFFlowMod.Builder fmb = sw.getOFFactory().buildFlowAdd(); // Define  a nova entrada da tabela de fluxo.
		OFActionOutput.Builder aob = sw.getOFFactory().actions().buildOutput(); // Define a acao a ser tomada para um dado grupo de pacotes.
		Match.Builder mb = sw.getOFFactory().buildMatch(); // Define a regra de matching dos pacotes.
		String switchId = sw.getId().toString(); //Obtem o ID do switch.
		List<OFAction> actions = new ArrayList<OFAction>(); // Encapsula as acoes definidas.
		OFPort outPort = OFPort.ZERO; // Porta de saida selecionada para o pacote.
		
		boolean flag = true;
		
		//Protocolo ARP.
		if (eth.getEtherType() == EthType.ARP) {
			IPv4Address arpSpa = ((ARP) eth.getPayload()).getSenderProtocolAddress();// IP de origem dos pacotes do protocolo ARP.
			String sourceIp = arpSpa.toInetAddress().toString(); //IP do host de origem.

			//Origem no Host H1.
			if(sourceIp.equals(IpH1)){
				switch(switchId){
					case Switch1:
						outPort = Port_S1_S2;
						break;
						
					case Switch2:
						outPort = Port_S2_S4;
						break;
						
					case Switch4:
						outPort = Port_S4_H2;
						break;
				}
			}
			
			//Origem no Host H2.
			else if (sourceIp.equals(IpH2)){
				switch(switchId){
					case Switch4:
						outPort = Port_S4_S3;
						break;
						
					case Switch3:
						outPort = Port_S3_S1;
						break;
						
					case Switch1:
						outPort = Port_S1_H1;
						break;
				}
			}
			
			//Se o host nao for nem H1 nem H2.
			else
				return Command.CONTINUE;
			
			//Define as regras de mathcing.
			mb.setExact(MatchField.ETH_TYPE, EthType.ARP); //Protocolo ARP.
			mb.setExact(MatchField.ARP_SPA, arpSpa); //IP de origem.
		}
		
		//Protocolos IPv4.
		else if (eth.getEtherType() == EthType.IPv4) {
			IPv4 ipv4 = (IPv4) eth.getPayload(); //Obtem os dados do pacote IPv4.
			IPv4Address srcIp = ipv4.getSourceAddress(); //Obtem os dados do IP de origem.
			IpProtocol ipProtocol = ipv4.getProtocol(); //Obtem o protocolo utilizado.
			String sourceIp = srcIp.toInetAddress().toString(); //Obtem a string com o IP do host de origem.
			
			//Define o IP de origem como parte da regra de matching.
			mb.setExact(MatchField.ETH_TYPE, EthType.IPv4);
			mb.setExact(MatchField.IPV4_SRC, srcIp);
			
			//Protocolo TCP.
			if (ipProtocol.equals(IpProtocol.TCP)) {
				TCP tcpPackage = ((TCP)ipv4.getPayload());
				
				//Define o mathcing de porta (de comunicacao) de destino/origem.--------
				mb.setExact(MatchField.IP_PROTO, IpProtocol.TCP); //Define o protocolo IP de mathcing como TCP.
				
				TransportPort port = tcpPackage.getDestinationPort(); //Obtem os dados da porta de destino.
				
				//Se a porta de destino do mathcing caso a porta de DESTINO do TCP seja 21 ou 80.
				if(port.getPort() == 21 || port.getPort() == 80)
					mb.setExact(MatchField.TCP_DST, port);
				
				//Se a porta de destino do mathcing caso a porta de ORIGEM do TCP seja 21 ou 80.
				else if ((port = tcpPackage.getSourcePort()).getPort() == 21  || port.getPort() == 80)
					mb.setExact(MatchField.TCP_SRC, port);
				
				//Caso nenhuma das portas seja 21 ou 80.
				else
					return Command.CONTINUE;
				//----------------------------------------------------------------------
				
				//Host H1.
				if(sourceIp.equals(IpH1)){
					
					//Seleciona acao por numero da porta TCP.
					switch(port.getPort()){
						
						//FTP.
						case 21:
							switch(switchId){
							case Switch1:
								outPort = Port_S1_S2;
								break;
							case Switch2:
								flag = false;
								break;
						}
							//outPort = switchId.equals(Switch1) ? Port_S1_S2 : OFPort.ZERO; //Switch 1 envia para Switch 2, Switch 2 dropa.
							/*if(switchId.equals(Switch1)){
								flag = false;
							}*/ //Switch 1 envia para Switch 2, Switch 2 dropa.
							break;
						
						//HTTP.
						case 80:
							switch(switchId){
								case Switch1:
									outPort = Port_S1_S3;
									break;
									
								case Switch3:
									outPort = Port_S3_S4;
									break;
									
								case Switch4:
									outPort = Port_S4_H2;
									break;
							}
							break;
					}
					
				}
				
				//Host H2.
				else if(sourceIp.equals(IpH2)){
					switch(port.getPort()){
						
						//FTP.
						case 21:
							switch(switchId){
								case Switch4:
									outPort = Port_S4_S2;
									break;
								case Switch2:
									flag = false;
									break;
							}
							//outPort = switchId.equals(Switch4) ? Port_S4_S2 : OFPort.ZERO; //Switch 4 envia para Switch 2, Switch 2 dropa.
							
							/*if(switchId.equals(Switch4)){
								flag = false;
							}*/
							
							break;
						
						//HTTP.
						case 80:
							switch(switchId){
								case Switch4:
									outPort = Port_S4_S3;
									break;
									
								case Switch3:
									outPort = Port_S3_S1;
									break;
									
								case Switch1:
									outPort = Port_S1_H1;
									break;
							}
							break;
					}
				}
				
				//Se nao for H1 nem H2.
				else
					return Command.CONTINUE;
			}
			
			//Se nao for TCP.
			else
				return Command.CONTINUE;
		}
		
		//se nao for ARP ou IPv4.
		else
			return Command.CONTINUE;
		
		//Define as informacoes a serem escritas no switch.---------------- 
		//Define a porta de saida.
		if(flag){
			aob.setPort(outPort);
			aob.setMaxLen(Integer.MAX_VALUE);
			actions.add(aob.build());
		}
		fmb.setActions(actions);
		fmb.setMatch(mb.build());
		fmb.setBufferId(OFBufferId.NO_BUFFER);
		fmb.setIdleTimeout(60); //Define o tempo de duracao da regra.
		fmb.setPriority(7); //Define a prioridade.
		//-----------------------------------------------------------------

		sw.write(fmb.build()); //Envia as informacoes para o switch.

		return Command.STOP; //Previne a interferencia de outros modulos.
	}

}