import heapq
from collections import defaultdict

class Graph(object):
    def __init__(self):
        self.edges = defaultdict(list)
        self.heap=[]
        self.dist = dict()
        self.pre = {}
        self.visited = {}

    def add_edge(self, src, dst, weight=1):
        self.edges[src].append((src, dst, weight))
    """
    djkistra returns two dicts:
        pre: previous node of dst
        dist: distance to dst
    """

    def djikstra(self, src):
        self.dist = {src: 0}
        heapq.heappush(self.heap, (self.dist[src], src))

        while len(self.heap) > 0:
            d, curr = heapq.heappop(self.heap)
            if curr in self.visited:
                continue
            self.visited[curr] = True
            for edge in self.edges[curr]:
                edge_src, edge_dst, edge_weight = edge
                new_dist = d + edge_weight
                dst = edge_dst
                if dst not in self.dist or new_dist < self.dist[dst]:
                    self.dist[dst] = new_dist
                    self.pre[dst] = curr
                    heapq.heappush(self.heap, (new_dist, dst))
        return self.pre, self.dist
    """
    fetch_next_hop return a dict:
        key:
            dst node
        value:
            (next_hop, total distance)
    """
    def fetch_next_hop(self, src):
        chain, distance = self.djikstra(src)
        result = {}
        for node in chain:
            curr = node
            while curr != src:
                next_node = curr
                curr = chain[curr]
            result[node] = (next_node, distance[node])
        return result
