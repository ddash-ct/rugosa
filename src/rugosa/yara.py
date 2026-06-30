"""
Utility for running YARA within the context of a disassembly.

This utility extends and overwrites the existing YARA API to work correctly within a dragodis context.

usage::
    from rugosa import yara

    # Compile a yara rule in the same way as the original yara library.
    rule = yara.compile(source=rule_text)

    with dragodis.open_program("input.exe") as dis:
        matches = rule.match(dis)  # Run rule on entire disassembled code.

        # Can also be used to run on segments.
        matches = rule.match(dis, segment='.text')

        # We can also just look for matching strings.
        for offset, identifer in rule.match_strings(dis):
            # ...
        for offset, identifer in rule.match_strings(dis, segment='.text'):
            # ...
"""

from __future__ import annotations
import logging
from typing import Iterable, List, Tuple, Union, Any

import dragodis
from dragodis.interface import Function
import yara_x


logger = logging.getLogger(__name__)

READ_LENGTH = 10485760  # 10 MB


class StringMatchInstance:
    """
    Patches yara.StringMatchInstance to convert strings offsets to virtual addresses.
    """

    def __init__(self, string_match_instance, dis: dragodis.Disassembler, offset=None, file_offset=False):
        self._string_match_instance = string_match_instance
        self._dis = dis
        self._offset = offset
        self._file_offset = file_offset
        self.__offset = None

    def __getattr__(self, item):
        return getattr(self._string_match_instance, item)

    def __str__(self):
        return str(self._string_match_instance)

    def __repr__(self):
        return repr(self._string_match_instance)

    @property
    def offset(self) -> int:
        """
        Patched yara.StringMatchInstance.offset to provide address instead.
        """
        if self.__offset is None:
            offset = self._string_match_instance.offset
            if self._offset is not None:
                offset += self._offset
            if self._file_offset:
                offset = self._dis.get_virtual_address(offset)
            addr = self._dis.get_line(offset).address
            self.__offset = addr
        return self.__offset


class StringMatch:
    """
    Patches yara.StringMatch to convert strings offsets to virtual addresses.
    """

    def __init__(self, string_match, dis: dragodis.Disassembler, offset=None, file_offset=False):
        self._string_match = string_match
        self._dis = dis
        self._offset = offset
        self._file_offset = file_offset
        self._instances = None

    def __getattr__(self, item):
        return getattr(self._string_match, item)

    def __str__(self):
        return str(self._string_match)

    def __repr__(self):
        return repr(self._string_match)

    @property
    def instances(self) -> List[StringMatchInstance]:
        if self._instances is None:
            self._instances = [
                StringMatchInstance(string_match_instance, self._dis, offset=self._offset, file_offset=self._file_offset)
                for string_match_instance in self._string_match.instances
            ]
        return self._instances


class Match:
    """
    Patches yara_x.Pattern to  convert string offsets to virtual addresses.

    NOTE: We can't inherit yara.Match because they don't expose that class.

    :param yara_x.Pattern match_object: Original match object created by YARA
    :param dragodis.Disasssembler dis: Dragodis disassembler
    :param int offset: Optional offset to offset string offsets by
    :param bool file_offset: Whether string offsets will be the file offset and should be converted.
    """

    def __init__(self, match_object: yara_x.Pattern, dis: dragodis.Disassembler, offset: int = None, file_offset: bool = False):
        self._match = match_object
        self._dis = dis
        self._offset = offset
        self._file_offset = file_offset
        self._strings = None

    def __getattr__(self, item):
        return getattr(self._match, item)

    def __str__(self):
        return str(self._match)

    def __repr__(self):
        return repr(self._match)

    @property
    def strings(self) -> Union[List[Tuple[int, Any, Any]], List[StringMatch]]:
        if self._strings is not None:
            return self._strings

        self._strings = []

        for entry in self._match.matches:
            offset = entry.offset
            if self._offset is not None:
                offset += self._offset
            if self._file_offset:
                offset = self._dis.get_virtual_address(offset)
            addr = self._dis.get_line(offset).address
            self._strings.append((addr, self._match.identifier, self._dis.get_bytes(addr, entry.length)))

        return self._strings


class Rules:
    """
    Patches yara.Rules to use our patched Match object when match() is called.

    NOTE: We can't inherit yara.Rules because they don't expose that class.
    """

    def __init__(self, rules_object):
        self._rules = rules_object

    def __getattr__(self, item):
        return getattr(self._rules, item)

    def match(
            self, dis: dragodis.Disassembler, *args,
            input_offset=False, offset: int = None, segment: Union[str, int] = None,
            **kwargs
    ) -> List[Match]:
        """
        Patched to use our patched Match() object and allow for automatically running
        on IDB input file.

        Besides the default yara parameters, this implementation also includes:
            :param dis: Dragodis disassembler.
            :param *args: Positional arguments to pass to underlying yara.match() call.
            :param input_offset: Whether to apply input file offset to string offsets.
            :param offset: Optional offset to offset string offsets by.
            :param segment: Name or EA of segment to match to.
            :param legacy_strings: Whether to present Match.strings as a tuple of
                (<offset>, <string identifier>, <string data>) as it was presented before YARA 4.3.0.
            :param **kwargs: Keyword arguments to pass to underlying yara.match() call.
        """

        # Run on segment.
        if segment:
            segment = dis.get_segment(segment)
            data = segment.data
            offset = offset or segment.start
        # Run on input file.
        else:
            data = dis.input_path.read_bytes()
            input_offset = True

        matches = list()
        for rule in self._rules.scan(data).matching_rules:
            for pattern in rule.patterns:
                if pattern.matches:
                    matches.append(Match(pattern, dis, offset=offset, file_offset=input_offset))

        return matches

    def match_strings(self, *args, **kwargs) -> List[Tuple[int, str]]:
        """
        Runs match() but then returns tuples containing matched strings instead of Match objects.

        (This replicates the original legacy _YARA_MATCHES output)

        :returns: Tuple containing: (offset, identifier)
        """
        matched_strings = []
        for match in self.match(*args, legacy_strings=True, **kwargs):
            for offset, identifier, _ in match.strings:
                matched_strings.append((offset, identifier))
        return matched_strings

    def find_functions(self, dis: dragodis.Disassembler, *args, **kwargs) -> Iterable[Function]:
        """
        Iterates functions that match the given rule text.
        """
        cache = set()
        for match in self.match(dis, *args, legacy_strings=True, **kwargs):
            for ea, _, _ in match.strings:
                try:
                    func = dis.get_function(ea)
                except dragodis.NotExistError:
                    continue

                if func.start not in cache:
                    cache.add(func.start)
                    yield func


def compile(rule_text: str) -> Rules:
    """Wraps compiled rule in our patched Rules object."""
    return Rules(yara_x.compile(rule_text))


# Convenience functions ==============


def match(dis: dragodis.Disassembler, rule_text: str, *args, **kwargs) -> List[Match]:
    """Returns list of Match objects"""
    rule = compile(rule_text)
    return rule.match(dis, *args, **kwargs)


def match_strings(dis: dragodis.Disassembler, rule_text: str, *args, **kwargs) -> List[Tuple[int, str]]:
    """Returns list of (offset, string identifier)"""
    rule = compile(rule_text)
    return rule.match_strings(dis, *args, **kwargs)


def find_functions(dis: dragodis.Disassembler, rule_text: str, *args, **kwargs) -> Iterable[Function]:
    """
    Iterates functions that match the given rule text.
    """
    rule = compile(rule_text)
    yield from rule.find_functions(dis, *args, **kwargs)

# ====================================
