/*
 * tree_k_ary.d: Simple k-ary tree implementation, inspired by http://tree.phi-sci.com/
 *
 * Copyright (C) 2018, 2019  Carsten Blüggel <bluecars@posteo.eu>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335  USA.
 */

/* Written in the D programming language */

/*
   http://tree.phi-sci.com/ : tree.hh: an STL-like C++ tree class by Kasper Peeters
   This is a stripped down version from other code, to meet current needs
*/

module tree_k_ary;

import std.experimental.allocator.gc_allocator;
import std.conv : emplace;
import std.functional : binaryFun;

nothrow
struct Tree_k_ary(T, Alloc=GCAllocator)
{
    version(unittest)
    static int countNodes;

    alias nodeType  = TreeNode;
//  alias valueType = T;

    TreeNode* head;
    TreeNode* feet;

    TreeNode* root() { return head.nextSibling; }

    struct TreeNode
    {
        T data;
        TreeNode* parent, firstChild, lastChild, prevSibling, nextSibling;
    }

    static Tree_k_ary opCall()
    {
        Tree_k_ary t;
        t.head = cast(TreeNode*)Alloc.instance.allocate(TreeNode.sizeof).ptr;
        t.feet = cast(TreeNode*)Alloc.instance.allocate(TreeNode.sizeof).ptr;

        t.head.parent      = null;
        t.head.firstChild  = null;
        t.head.lastChild   = null;
        t.head.prevSibling = null;
        t.head.nextSibling = t.feet;

        t.feet.parent      = null;
        t.feet.firstChild  = null;
        t.feet.lastChild   = null;
        t.feet.prevSibling = t.head;
        t.feet.nextSibling = null;
        return t;
    }
/+
    RangePreOrder opSlice()
    {
        if (root()==feet)
            return RangePreOrder(feet, feet);
        else
            return RangePreOrder(root(), feet);
    }
+/
/+
    TreeNode* setRoot(T x)
    {
        return insertAsSiblingBefore(feet, x); // if there is 1 root only, it's the same as insertAsSiblingAfter(head, x);
    }
+/

    TreeNode* insertAsSiblingBefore(TreeNode* pos, T x)
    {
        if (pos == null)
            pos = feet; // Backward compatibility: when calling insert on a null node, insert before the feet.
        assert(pos != head); // Cannot insert before head.

        version(unittest)
            ++countNodes;
        auto tmp = cast(TreeNode*)Alloc.instance.allocate(TreeNode.sizeof).ptr;
        emplace(&tmp.data, x);
        tmp.parent      = pos.parent;
        tmp.firstChild  = null;
        tmp.lastChild   = null;
        tmp.nextSibling = pos;
        tmp.prevSibling = pos.prevSibling;
        pos.prevSibling = tmp;

        if (tmp.prevSibling != null)
            tmp.prevSibling.nextSibling = tmp;
        else
            if (tmp.parent) // when inserting nodes at the head, there is no parent
                tmp.parent.firstChild = tmp;
        return tmp;
    }

    TreeNode* insertAsSiblingAfter(TreeNode* pos, T x)
    {
        if (pos == null)
            pos = head; // Backward compatibility: when calling insert on a null node, insert after the head.
        assert(pos != feet); // Cannot insert after feet.

        version(unittest)
            ++countNodes;
        auto tmp = cast(TreeNode*)Alloc.instance.allocate(TreeNode.sizeof).ptr;
        emplace(&tmp.data, x);
        tmp.parent      = pos.parent;
        tmp.firstChild  = null;
        tmp.lastChild   = null;
        tmp.prevSibling = pos;
        tmp.nextSibling = pos.nextSibling;
        pos.nextSibling = tmp;

        if (tmp.nextSibling != null)
            tmp.nextSibling.prevSibling = tmp;
        else
            if (tmp.parent) // when inserting nodes at the head, there is no parent
                tmp.parent.lastChild = tmp;
        return tmp;
    }

    /// Insert node as first child of node pointed to by posParent.
    TreeNode* insertAsChildFirst(TreeNode* posParent, T x)
    {
        assert(posParent != head);
        assert(posParent != feet);
        assert(posParent);

        version(unittest)
            ++countNodes;
        auto tmp = cast(TreeNode*)Alloc.instance.allocate(TreeNode.sizeof).ptr;
        emplace(&tmp.data, x);
        tmp.parent     = posParent;
        tmp.firstChild = null;
        tmp.lastChild  = null;
        tmp.prevSibling = null;

        if (posParent.firstChild != null)
            posParent.firstChild.prevSibling = tmp;
        else
            posParent.lastChild = tmp;
        tmp.nextSibling = posParent.firstChild;
        posParent.firstChild = tmp;
        return tmp;
    }

    /// Insert node as last child of node pointed to by posParent.
    TreeNode* insertAsChildLast(TreeNode* posParent, T x)
    {
        assert(posParent != head);
        assert(posParent != feet);
        assert(posParent);

        version(unittest)
            ++countNodes;
        auto tmp = cast(TreeNode*)Alloc.instance.allocate(TreeNode.sizeof).ptr;
        emplace(&tmp.data, x);
        tmp.parent     = posParent;
        tmp.firstChild = null;
        tmp.lastChild  = null;
        tmp.nextSibling = null;

        if (posParent.lastChild != null)
            posParent.lastChild.nextSibling = tmp;
        else
            posParent.firstChild = tmp;
        tmp.prevSibling = posParent.lastChild;
        posParent.lastChild = tmp;
        return tmp;
    }

    /// Erase all children of the node pointed to by posParent
    void eraseChildren(TreeNode* posParent)
    {
        if (posParent==null)
            return;

        TreeNode* prev;
        TreeNode* cur  = posParent.firstChild;

        while (cur != null)
        {
            prev = cur;
            cur  = cur.nextSibling;
            eraseChildren(prev);

            version(unittest)
                --countNodes;
            Alloc.instance.deallocate((cast(void*)prev)[0..TreeNode.sizeof]);
        }
        posParent.firstChild = null;
        posParent.lastChild  = null;
    }

    /// Erase element at position pointed to by pos, return pos.nextSibling
    TreeNode* erase(TreeNode* pos)
    {
        assert(pos);
        assert(pos != head);
        assert(pos != feet);
        eraseChildren(pos);
        if (pos.prevSibling != null)
            pos.prevSibling.nextSibling = pos.nextSibling;
        else
        {
            if (pos.parent)      pos.parent.firstChild = pos.nextSibling;
            if (pos.nextSibling) pos.nextSibling.prevSibling = null;
        }

        if (pos.nextSibling != null)
            pos.nextSibling.prevSibling = pos.prevSibling;
        else
        {
            if (pos.parent)      pos.parent.lastChild = pos.prevSibling;
            if (pos.prevSibling) pos.prevSibling.nextSibling = null;
        }

        TreeNode* tmp = pos.nextSibling;
        version(unittest)
            --countNodes;
        Alloc.instance.deallocate((cast(void*)pos)[0..TreeNode.sizeof]);
        return tmp;
    }

    /// Erase all nodes of the tree.
    void clear()
    {
        if (head)
        {
            TreeNode* tmp = root();
            while (tmp != feet)
                tmp = erase(tmp);
        }
    }

    struct RangePreOrder
    {
        TreeNode* currNode;
        TreeNode* endNode; // must be set to feet
        @property TreeNode* front() { return currNode; }
        @property bool empty() { return currNode == endNode; }

        void popFront()
        {
            if (currNode.firstChild != null)
            {
                currNode = currNode.firstChild;
                return;
            }
            else
            {
                while (currNode.nextSibling == null)
                    currNode = currNode.parent;

                currNode = currNode.nextSibling;
                return;
            }
        }

        TreeNode* locate(alias pred="a.data==b", E)(E needle) nothrow /*@nogc*/
        {
            for ( ; !empty(); popFront())
                if (binaryFun!pred(front(), needle))
                    return currNode;
            return typeof(return).init;
        }
    }

    RangePreOrder rangePreOrder() { return RangePreOrder(root(), feet); }

    struct RangeSiblings
    {
        @safe unittest
        {
            import std.range.primitives : isBidirectionalRange;
            static assert(isBidirectionalRange!RangeSiblings);
        }

        private TreeNode* _first;
        private TreeNode* _last;

        private this(TreeNode* parent) { assert(parent); _first = parent.firstChild; _last = parent.lastChild; }

        @property bool empty() { return !_first; }
        @property RangeSiblings save() { return this; }

        @property TreeNode* front() { return _first; }
        @property TreeNode* back()  { return _last; }
        void popFront()
        {
            if (_first is _last)
                _first = _last = null;
            else
                _first = _first.nextSibling;
        }

        void popBack()
        {
            if (_first is _last)
                _first = _last = null;
            else
                _last = _last.prevSibling;
        }

        TreeNode* locate(alias pred="a.data==b", E)(E needle) nothrow /*@nogc*/
        {
            for ( ; !empty(); popFront())
                if (binaryFun!pred(front(), needle))
                    return _first;
            return typeof(return).init;
        }
    }

    RangeSiblings rangeSiblings(TreeNode* parent) { return RangeSiblings(parent); }
}

unittest
{
    import std.algorithm.comparison : equal;
    import std.range : retro;

    auto t = Tree_k_ary!int();
    assert(t.head.parent      == null);
    assert(t.head.firstChild  == null);
    assert(t.head.lastChild   == null);
    assert(t.head.prevSibling == null);
    assert(t.head.nextSibling == t.feet);

    assert(t.feet.parent      == null);
    assert(t.feet.firstChild  == null);
    assert(t.feet.lastChild   == null);
    assert(t.feet.prevSibling == t.head);
    assert(t.feet.nextSibling == null);

    auto n1 = t.insertAsSiblingAfter(null, 1);
//  auto n1 = t.insertAsSiblingBefore(null, 1); // alternative
    assert(t.head.parent      == null);
    assert(t.head.firstChild  == null);
    assert(t.head.lastChild   == null);
    assert(t.head.prevSibling == null);
    assert(t.head.nextSibling == n1);

    assert(n1.parent      == null);
    assert(n1.firstChild  == null);
    assert(n1.lastChild   == null);
    assert(n1.prevSibling == t.head);
    assert(n1.nextSibling == t.feet);

    assert(t.feet.parent      == null);
    assert(t.feet.firstChild  == null);
    assert(t.feet.lastChild   == null);
    assert(t.feet.prevSibling == n1);
    assert(t.feet.nextSibling == null);

    auto n2 = t.insertAsSiblingBefore(null, 2);
//  auto n2 = t.insertAsSiblingAfter(n1, 2); // alternative
    assert(t.head.parent      == null);
    assert(t.head.firstChild  == null);
    assert(t.head.lastChild   == null);
    assert(t.head.prevSibling == null);
    assert(t.head.nextSibling == n1);

    assert(n1.parent      == null);
    assert(n1.firstChild  == null);
    assert(n1.lastChild   == null);
    assert(n1.prevSibling == t.head);
    assert(n1.nextSibling == n2);

    assert(n2.parent      == null);
    assert(n2.firstChild  == null);
    assert(n2.lastChild   == null);
    assert(n2.prevSibling == n1);
    assert(n2.nextSibling == t.feet);

    assert(t.feet.parent      == null);
    assert(t.feet.firstChild  == null);
    assert(t.feet.lastChild   == null);
    assert(t.feet.prevSibling == n2);
    assert(t.feet.nextSibling == null);

// test insertAsChildFirst and insertAsSiblingBefore
    auto n6 = t.insertAsChildFirst(n1, 6);
    assert(n1.parent      == null);
    assert(n1.firstChild  == n6);
    assert(n1.lastChild   == n6);
    assert(n1.prevSibling == t.head);
    assert(n1.nextSibling == n2);

    assert(n6.parent      == n1);
    assert(n6.firstChild  == null);
    assert(n6.lastChild   == null);
    assert(n6.prevSibling == null);
    assert(n6.nextSibling == null);

    auto n4 = t.insertAsChildFirst(n1, 4);
    assert(n1.parent      == null);
    assert(n1.firstChild  == n4);
    assert(n1.lastChild   == n6);
    assert(n1.prevSibling == t.head);
    assert(n1.nextSibling == n2);

    assert(n4.parent      == n1);
    assert(n4.firstChild  == null);
    assert(n4.lastChild   == null);
    assert(n4.prevSibling == null);
    assert(n4.nextSibling == n6);

    assert(n6.parent      == n1);
    assert(n6.firstChild  == null);
    assert(n6.lastChild   == null);
    assert(n6.prevSibling == n4);
    assert(n6.nextSibling == null);

    auto n3 = t.insertAsSiblingBefore(n4, 3);
    assert(n1.parent      == null);
    assert(n1.firstChild  == n3);
    assert(n1.lastChild   == n6);
    assert(n1.prevSibling == t.head);
    assert(n1.nextSibling == n2);

    assert(n3.parent      == n1);
    assert(n3.firstChild  == null);
    assert(n3.lastChild   == null);
    assert(n3.prevSibling == null);
    assert(n3.nextSibling == n4);

    assert(n4.parent      == n1);
    assert(n4.firstChild  == null);
    assert(n4.lastChild   == null);
    assert(n4.prevSibling == n3);
    assert(n4.nextSibling == n6);

    auto n5 = t.insertAsSiblingBefore(n6, 5);
    assert(n1.parent      == null);
    assert(n1.firstChild  == n3);
    assert(n1.lastChild   == n6);
    assert(n1.prevSibling == t.head);
    assert(n1.nextSibling == n2);

    assert(n4.parent      == n1);
    assert(n4.firstChild  == null);
    assert(n4.lastChild   == null);
    assert(n4.prevSibling == n3);
    assert(n4.nextSibling == n5);

    assert(n5.parent      == n1);
    assert(n5.firstChild  == null);
    assert(n5.lastChild   == null);
    assert(n5.prevSibling == n4);
    assert(n5.nextSibling == n6);

    assert(n6.parent      == n1);
    assert(n6.firstChild  == null);
    assert(n6.lastChild   == null);
    assert(n6.prevSibling == n5);
    assert(n6.nextSibling == null);

// test insertAsChildLast and insertAsSiblingAfter
    auto n7 = t.insertAsChildLast(n2, 7);
    assert(n2.parent      == null);
    assert(n2.firstChild  == n7);
    assert(n2.lastChild   == n7);
    assert(n2.prevSibling == n1);
    assert(n2.nextSibling == t.feet);

    assert(n7.parent      == n2);
    assert(n7.firstChild  == null);
    assert(n7.lastChild   == null);
    assert(n7.prevSibling == null);
    assert(n7.nextSibling == null);

    auto n9 = t.insertAsChildLast(n2, 9);
    assert(n2.parent      == null);
    assert(n2.firstChild  == n7);
    assert(n2.lastChild   == n9);
    assert(n2.prevSibling == n1);
    assert(n2.nextSibling == t.feet);

    assert(n9.parent      == n2);
    assert(n9.firstChild  == null);
    assert(n9.lastChild   == null);
    assert(n9.prevSibling == n7);
    assert(n9.nextSibling == null);
//
    auto n8 = t.insertAsSiblingAfter(n7, 8);
    assert(n2.parent      == null);
    assert(n2.firstChild  == n7);
    assert(n2.lastChild   == n9);
    assert(n2.prevSibling == n1);
    assert(n2.nextSibling == t.feet);

    assert(n7.parent      == n2);
    assert(n7.firstChild  == null);
    assert(n7.lastChild   == null);
    assert(n7.prevSibling == null);
    assert(n7.nextSibling == n8);

    assert(n8.parent      == n2);
    assert(n8.firstChild  == null);
    assert(n8.lastChild   == null);
    assert(n8.prevSibling == n7);
    assert(n8.nextSibling == n9);

    assert(n9.parent      == n2);
    assert(n9.firstChild  == null);
    assert(n9.lastChild   == null);
    assert(n9.prevSibling == n8);
    assert(n9.nextSibling == null);

    auto n10 = t.insertAsSiblingAfter(n9, 10);
    assert(n2.parent      == null);
    assert(n2.firstChild  == n7);
    assert(n2.lastChild   == n10);
    assert(n2.prevSibling == n1);
    assert(n2.nextSibling == t.feet);

    assert(n9.parent      == n2);
    assert(n9.firstChild  == null);
    assert(n9.lastChild   == null);
    assert(n9.prevSibling == n8);
    assert(n9.nextSibling == n10);

    assert(n10.parent      == n2);
    assert(n10.firstChild  == null);
    assert(n10.lastChild   == null);
    assert(n10.prevSibling == n9);
    assert(n10.nextSibling == null);

    assert(t.countNodes==10);
    int[] w;
    w.reserve(10);

    foreach (e; t.rangePreOrder())
        w ~= e.data;
    assert(equal(w, [1,3,4,5,6, 2,7,8,9,10]));

    w = null;
    foreach (e; t.rangeSiblings(n1))
        w ~= e.data;
    assert(equal(w, [3,4,5,6]));
    w = null;
    foreach (e; t.rangeSiblings(n1).retro)
        w ~= e.data;
    assert(equal(w, [6,5,4,3]));

    auto someNode = t.rangePreOrder().locate(1);
    assert(someNode == n1);

    t.eraseChildren(n1);
    assert(t.countNodes==6);
    assert(n1.parent      == null);
    assert(n1.firstChild  == null);
    assert(n1.lastChild   == null);
    assert(n1.prevSibling == t.head);
    assert(n1.nextSibling == n2);

    auto en10 = t.erase(n9);
    assert(en10 == n10);
    assert(t.countNodes==5);
    assert(n2.parent      == null);
    assert(n2.firstChild  == n7);
    assert(n2.lastChild   == n10);
    assert(n2.prevSibling == n1);
    assert(n2.nextSibling == t.feet);

    assert(n8.parent      == n2);
    assert(n8.firstChild  == null);
    assert(n8.lastChild   == null);
    assert(n8.prevSibling == n7);
    assert(n8.nextSibling == n10);

    assert(n10.parent      == n2);
    assert(n10.firstChild  == null);
    assert(n10.lastChild   == null);
    assert(n10.prevSibling == n8);
    assert(n10.nextSibling == null);

    t.erase(n10);
    assert(t.countNodes==4);
    assert(n2.parent      == null);
    assert(n2.firstChild  == n7);
    assert(n2.lastChild   == n8);
    assert(n2.prevSibling == n1);
    assert(n2.nextSibling == t.feet);

    assert(n8.parent      == n2);
    assert(n8.firstChild  == null);
    assert(n8.lastChild   == null);
    assert(n8.prevSibling == n7);
    assert(n8.nextSibling == null);

    t.erase(n7);
    assert(t.countNodes==3);
    assert(n2.parent      == null);
    assert(n2.firstChild  == n8);
    assert(n2.lastChild   == n8);
    assert(n2.prevSibling == n1);
    assert(n2.nextSibling == t.feet);

    assert(n8.parent      == n2);
    assert(n8.firstChild  == null);
    assert(n8.lastChild   == null);
    assert(n8.prevSibling == null);
    assert(n8.nextSibling == null);

    t.erase(n8);
    assert(t.countNodes==2);
    assert(n2.parent      == null);
    assert(n2.firstChild  == null);
    assert(n2.lastChild   == null);
    assert(n2.prevSibling == n1);
    assert(n2.nextSibling == t.feet);

    t.clear();
    assert(t.countNodes==0);
    assert(t.head.parent      == null);
    assert(t.head.firstChild  == null);
    assert(t.head.lastChild   == null);
    assert(t.head.prevSibling == null);
    assert(t.head.nextSibling == t.feet);

    assert(t.feet.parent      == null);
    assert(t.feet.firstChild  == null);
    assert(t.feet.lastChild   == null);
    assert(t.feet.prevSibling == t.head);
    assert(t.feet.nextSibling == null);
}

unittest
{
    import std.algorithm.comparison : equal;
//    import std.stdio;

    auto t = Tree_k_ary!string();
    auto nF = t.insertAsSiblingAfter(null, "F");
    auto nB = t.insertAsChildLast(nF, "B");
    auto nG = t.insertAsChildLast(nF, "G");
    auto nA = t.insertAsChildLast(nB, "A");
    auto nD = t.insertAsChildLast(nB, "D");
              t.insertAsChildLast(nD, "C");
              t.insertAsChildLast(nD, "E");
    auto nI = t.insertAsChildLast(nG, "I");
              t.insertAsChildLast(nI, "H");
    string[] w;
    foreach (e; t.rangePreOrder())
        w ~= e.data;
    assert(equal(w, ["F", "B", "A", "D", "C", "E", "G", "I", "H"]));
    assert(t.countNodes==9);

    t.erase(nD);
    assert(t.countNodes==6);
    assert(nB.parent      == nF);
    assert(nB.firstChild  == nA);
    assert(nB.lastChild   == nA);
    assert(nB.prevSibling == null);
    assert(nB.nextSibling == nG);

    assert(nA.parent      == nB);
    assert(nA.firstChild  == null);
    assert(nA.lastChild   == null);
    assert(nA.prevSibling == null);
    assert(nA.nextSibling == null);
}
