
def analyze_ast(ast, patterns):

    subpatterns = generate_subpatterns(patterns)
    vulnerabilities = []

    for sp in subpatterns:
        source = sp['source']
        sanitizer = sp['sanitizer']
        sink = sp['sink']
        implicit = sp['implicit']

        # Find all possible paths in nodes
        print(paths)

        # for path in paths:
        #     # Get all sources, sinks and sanitizers in the path
        #     sources_in_path = get_contained(path, source)
        #     sinks_in_path = get_contained(path, sink)
        #     sanitizers_in_path = get_contained(path, sanitizer)

        #     for source, sink in list(itertools.product(sources_in_path, sinks_in_path)):
        #         # Get all sources and sinks indexes
        #         source_indexes = [i for i, x in enumerate(path) if x == source]
        #         sink_indexes = [i for i, x in enumerate(path) if x == sink]

        #         # Get all the valid pairs of source -> sink
        #         source_sink_pairs = flow_pairs(source_indexes, sink_indexes)

        #         # Get all the sanitizers between the source -> sink pairs
        #         sanitizers_in_between = valid_sanitizers(
        #             sanitizers_in_path, path, source_sink_pairs)

        #         for (source_index, sink_index) in source_sink_pairs:
        #             vuln = {
        #                 "vulnerability": pattern['vulnerability'],
        #                 "source": path[source_index],
        #                 "sink": path[sink_index],
        #                 "sanitizer": sanitizers_in_between
        #             }
        #             if vuln not in possible_vulns:
        #                 possible_vulns.append(vuln)

        # # Remove duplicates (same path, same vuln) (hopefully)
        # possible_vulns = remove_duplicates(possible_vulns)

        # vulnerabilities.append(possible_vulns)

def get_contained(list1, list2):
    """
    A function that returns all communs between 2 litst
    """
    return [x for x in list1 for y in list2 if x == y]

def generate_subpatterns(patterns):
    """
    Generate all possible combinations of sources, sanitizers, and sinks
    """
    for pattern in patterns:
        sources = pattern['sources']
        sanitizers = pattern['sanitizers']
        sinks = pattern['sinks']
        implicit = pattern['implicit']

        subpatterns_list = []
        
        # Generate all possible combinations of sources, sanitizers, and sinks
        for source in sources:
            for sanitizer in sanitizers:
                for sink in sinks:
                    subpatterns_list.append({
                        "source": source,
                        "sanitizer": sanitizer,
                        "sink": sink,
                        "implicit": implicit
                    })

        return subpatterns_list