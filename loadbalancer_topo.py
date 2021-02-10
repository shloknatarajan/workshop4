from mininet.topo import Topo
 
 
class SimpleTopo(Topo):
    "Simple loop topology"
 
    def __init__(self):
        "Create custom loop topo."
 
        # Initialize topology
        Topo.__init__(self)
 
        # Add hosts and switches
        ## Add hosts        

        ## Add switches


        # Add links (Use the switches in then node1 space)
        # Link function prototye:
        ## mininet.net.Mininet.addLink( self, node1, node2, port1 = None, port2 = None, cls = None, params )       

 
topos = {'topology': (lambda: SimpleTopo())}

