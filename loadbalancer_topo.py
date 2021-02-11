from mininet.topo import Topo
 
 
class SimpleTopo(Topo):
    "Simple loop topology"
 
    def __init__(self):
        "Create custom loop topo."
 
        # Initialize topology
        Topo.__init__(self)
 
        # Add hosts and switches
        configuration = dict(bw=5, delay=None,max_queue_size=10, loss=0, use_htb=True)                
        ## Add hosts        
        h1 = self.addHost("h1")
        h2 = self.addHost("h2")
        h3 = self.addHost("h3")

        ## Add switches
        s1 = self.addSwitch("s1", protocols='OpenFlow13')
        s2 = self.addSwitch("s2", protocols='OpenFlow13')
        s3 = self.addSwitch("s3", protocols='OpenFlow13')
        s4 = self.addSwitch("s4", protocols='OpenFlow13')


        # Add links (Use the switches in then node1 space)
        self.addLink(s1, h1, 1)
        self.addLink(s1, s2, port1=2, port2=1)
        self.addLink(s1, s3, 3, 1)
        self.addLink(s3, s4, 2, 2)
        self.addLink(s2, s4, 2, 1)
        self.addLink(s4, h2, 3)
        self.addLink(s4, h3, 4)

        # Link function prototye:
        ## mininet.net.Mininet.addLink( self, node1, node2, port1 = None, port2 = None, cls = None, params )       

 
topos = {'topology': (lambda: SimpleTopo())}

