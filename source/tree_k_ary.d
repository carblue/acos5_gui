
//    STL-like templated tree class.
//
// Copyright (C) 2001-2015 Kasper Peeters <kasper@phi-sci.com>
// Distributed under the GNU General Public License version 3.
//
// Special permission to use tree.hh under the conditions of a
// different license can be requested from the author.

/** \mainpage tree.hh
    \author   Kasper Peeters
    \version  3.4
    \date     23-Jan-2016
    \see      http://tree.phi-sci.com/
    \see      http://tree.phi-sci.com/ChangeLog

   The tree.hh library for C++ provides an STL-like container class
   for n-ary trees, templated over the data stored at the
   nodes. Various types of iterators are provided (post-order,
   pre-order, and others). Where possible the access methods are
   compatible with the STL or alternative algorithms are
   available.
*/
/*
 * licence: The library is available under the terms of the GNU General Public License version 2 or 3 (see below).
 * The same holds for the D binding
 * k-ary tree
 * https://en.wikipedia.org/wiki/K-ary_tree
 *
 * http://www.martinbroadhurst.com/Graph-algorithms.html
 * https://code.dlang.org/packages/topological-sort
 * https://wiki.dlang.org/GSOC_2018_Ideas#std.graph
 * http://www.boost.org/doc/libs/1_66_0/libs/graph/doc/
 * https://github.com/WebDrake/Dgraph
 * http://igraph.org/redirect.html
 *
 * Think about (de-)serialization
#define tree_hh_
 */

module tree_k_ary;

import std.experimental.allocator;
import std.experimental.allocator.gc_allocator;// : GCAllocator;
import std.conv : emplace;
import std.functional : binaryFun;
import std.algorithm.comparison : equal;
//import std.stdio;

/+
#include <cassert>
#include <memory>
#include <stdexcept>
#include <iterator>
#include <set>
#include <queue>
#include <algorithm>
#include <cstddef>
+/

/// A node in the tree, combining links to other nodes as well as the actual data.
/+
template<class T>
class tree_node_ { // size: 5*4=20 bytes (on 32 bit arch), can be reduced by 8.
    public:
        tree_node_() :             parent(null), first_child(null), last_child(null), prev_sibling(null), next_sibling(null) {}
        tree_node_(const T& val) : parent(null), first_child(null), last_child(null), prev_sibling(null), next_sibling(null), data(val) {}
        tree_node_(T&& val)      : parent(null), first_child(null), last_child(null), prev_sibling(null), next_sibling(null), data(val) {}

        tree_node_<T> *parent;
        tree_node_<T> *first_child, *last_child;
        tree_node_<T> *prev_sibling, *next_siblings;
        T data;
};
+/
struct TreeNode(T) { // size: T.sizeof (+ padding) + 5*8=40 bytes (on 64 bit arch)
//if (__traits(compiles, T.init.dup))
//    public:
//        tree_node_();
//        tree_node_(const T&);
//        tree_node_(T&&);
    T         data;
    TreeNode* parent;
    TreeNode* firstChild;
    TreeNode* lastChild;
    TreeNode* prevSibling;
    TreeNode* nextSibling;

    this(/*const*/ ref T x) { data = x.dup; }
//    this(const     T x) { data = x; }
}


//template <class T, class tree_node_allocator = std::allocator<tree_node_<T> > >
//class tree {
struct Tree(T, Alloc=GCAllocator) {
////    protected:

    alias nodeType  = TreeNode!T; // typedef tree_node_<T> tree_node;
    alias valueType = T;          // typedef T value_type;

  public:
    nodeType* head;    // head/feet are always dummy; if an iterator points to them it is invalid
    nodeType* feet;
        /// Value of the data stored at a node.
/*
        class iterator_base;
        class pre_order_iterator;
        class post_order_iterator;
        class sibling_iterator;
        class leaf_iterator;
*/
//    this()                  { head_initialise_(); }                  // empty constructor
    this(/*const*/ ref T x) { head_initialise_(); set_head(x); }     // constructor setting given element as head
/+
        this(const /*ref*/ iterator_base other) {
            head_initialise_();
            set_head(*other);
            replace(begin(), other);
        }
        this(const ref Tree other) {          // copy constructor
            head_initialise_();
            copy_(other);
        }
+/
/*
        this(tree<T, tree_node_allocator>&& x) {                   // move constructor
            head_initialise_();
            if (x.head.nextSibling!=x.feet) { // move tree if non-empty only
                head.nextSibling = x.head.nextSibling;
                feet.prevSibling = x.head.prevSibling;
                x.head.nextSibling.prevSibling = head;
                x.feet.prevSibling.nextSibling = feet;
                x.head.nextSibling = x.feet;
                x.feet.prevSibling = x.head;
            }
        }
*/
    ~this() {
        clear();
        Alloc.instance.deallocate((cast(void*)head)[0..nodeType.sizeof]);
        Alloc.instance.deallocate((cast(void*)feet)[0..nodeType.sizeof]);
//            alloc_.destroy(head);
//            alloc_.destroy(feet);
//            alloc_.deallocate(head,1);
//            alloc_.deallocate(feet,1);
    }

    struct preOrderRange {
        pre_order_iterator  posSomeRoot;
        pre_order_iterator  posEnd;
        @disable this();
        this(pre_order_iterator pos, pre_order_iterator end) {
            posSomeRoot = new pre_order_iterator(pos);
            posEnd      = end;//new pre_order_iterator(feet);
        }
        @property bool empty() const  nothrow { return posSomeRoot.opEquals(posEnd); }
        void popFront()  nothrow { ++posSomeRoot; }
        @property T front() /*const*/  nothrow { assert(posSomeRoot.node); return posSomeRoot.node.data; }

        nodeType* locate(alias pred, E)(E needle) nothrow /*@nogc*/ {
            foreach (nodeType* pointer, elem; this)
                if (binaryFun!pred(elem, needle))
                    return pointer;
            return typeof(return).init;
        }

        int opApply(int delegate(T) nothrow dg) /*nothrow*/ {
            int result; /* continue as long as result==0 */
            for ( ; !empty(); popFront())
                if ((result= dg(front())) != 0)
                    break;
            return result;
        }
/+
        int opApply(int delegate(nodeType*) nothrow dg) nothrow {
            int result; /* continue as long as result==0 */
            for ( ; !empty(); popFront())
                if ((result= dg(posSomeRoot.node)) != 0)
                    break;
            return result;
        }
+/
        int opApply(int delegate(nodeType*, T) nothrow dg) /*nothrow*/ {
            int result; /* continue as long as result==0 */
            for ( ; !empty(); popFront())
                if ((result= dg(posSomeRoot.node, front())) != 0)
                    break;
            return result;
        }
/+
        int opApplyReverse(int delegate(nodeType*, T) dg) {
            int result; /* continue as long as result==0 */
//            nodeType* node;
            if (empty)
                return result;
            nodeType* end = posBegin.node;
            nodeType* tmp = posBegin.parent_.lastChild;
//            while (!empty()) {
//                tmp = posSomeRoot.node;
//                popFront();
//            }
            posBegin.node = tmp;
            for ( ; posBegin.node != end; --posBegin)
                if ((result= dg(posBegin.node, front())) != 0)
                    return result;
//            return result;
            return dg(posBegin.node, front());
        }
+/
        int opApply(int delegate(size_t, T) dg) {
            int result; /* continue as long as result==0 */
            size_t index;
            for ( ; !empty(); popFront())
                if ((result= dg(index++,front())) != 0)
                    break;
            return result;
        }

        int opApplyReverse(int delegate(T) dg) {
            int result; /* continue as long as result==0 */
            nodeType* end, tmp;
            end = tmp = posSomeRoot.node;
            while (!empty()) {
                tmp = posSomeRoot.node;
                popFront();
            }
            posSomeRoot.node = tmp;
            for ( ; posSomeRoot.node != end; --posSomeRoot)
                if ((result= dg(front())) != 0)
                    return result;
            return dg(front());
        }

    }
/+
    struct preOrderRangePointer {
        pre_order_iterator  posSomeRoot;
        pre_order_iterator  posEnd;
        @disable this();
        this(pre_order_iterator pos, pre_order_iterator end) {
            posSomeRoot = new pre_order_iterator(pos);
            posEnd      = end;//new pre_order_iterator(feet);
        }
        @property bool empty() const  nothrow { return posSomeRoot.opEquals(posEnd); }
        void popFront()  nothrow { ++posSomeRoot; }
        @property nodeType* front() /*const*/  nothrow { assert(posSomeRoot.node); return posSomeRoot.node; }

        nodeType* locate(alias pred, E)(E needle) nothrow /*@nogc*/ {
            foreach (elem; this)
                if (binaryFun!pred(elem, needle))
                    return elem;
            return typeof(return).init;
        }

        int opApply(int delegate(nodeType*) nothrow dg) nothrow {
            int result; /* continue as long as result==0 */
            for ( ; !empty(); popFront())
                if ((result= dg(front())) != 0)
                    break;
            return result;
        }
/+
        int opApply(int delegate(size_t, T) dg) {
            int result; /* continue as long as result==0 */
            size_t index;
            for ( ; !empty(); popFront())
                if ((result= dg(index++,front())) != 0)
                    break;
            return result;
        }

        int opApplyReverse(int delegate(T) dg) {
            int result; /* continue as long as result==0 */
            nodeType* end, tmp;
            end = tmp = posSomeRoot.node;
            while (!empty()) {
                tmp = posSomeRoot.node;
                popFront();
            }
            posSomeRoot.node = tmp;
            for ( ; posSomeRoot.node != end; --posSomeRoot)
                if ((result= dg(front())) != 0)
                    return result;
            return dg(front());
        }
+/
    }
+/
    struct postOrderRange {
        post_order_iterator  posSomeRoot;
        post_order_iterator  posEnd;
        @disable this();
        this(post_order_iterator pos, post_order_iterator end) {
            posSomeRoot = new post_order_iterator(pos);
            posEnd      = end;
        }
        @property bool empty() const { return posSomeRoot.opEquals(posEnd); }
        void popFront() { ++posSomeRoot; }
        @property T front() /*const*/ { assert(posSomeRoot.node); return posSomeRoot.node.data; }
    }

    struct siblingRange {
        sibling_iterator  posBegin;
        sibling_iterator  posEnd;
        @disable this();
        this(sibling_iterator b, sibling_iterator e) {
//            assert(pos_parent.node);
            posBegin = b;//Tree!T.begin(pos_parent);
            posEnd   = e;//Tree!T.end(pos_parent);
        }
        @property bool empty() const nothrow { return posBegin.opEquals(posEnd); }
        void popFront() nothrow { ++posBegin; }
        @property T front() /*const*/ nothrow { assert(posBegin.node); return posBegin.node.data; }

        nodeType* locate(alias pred, E)(E needle) /*@nogc*/ {
            foreach (nodeType* pointer, elem; this)
                if (binaryFun!pred(elem, needle))
                    return pointer;
            return typeof(return).init;
        }

        int opApply(int delegate(T) dg) {
            int result; /* continue as long as result==0 */
            for ( ; !empty(); popFront())
                if ((result= dg(front())) != 0)
                    break;
            return result;
        }

        int opApply(int delegate(nodeType*, T) dg) {
            int result; /* continue as long as result==0 */
            for ( ; !empty(); popFront())
                if ((result= dg(posBegin.node, front())) != 0)
                    break;
            return result;
        }

        int opApply(int delegate(size_t, T) dg) {
            int result; /* continue as long as result==0 */
            size_t index;
            for ( ; !empty(); popFront())
                if ((result= dg(index++,front())) != 0)
                    break;
            return result;
        }

        int opApplyReverse(int delegate(T) dg) {
            int result; /* continue as long as result==0 */
            if (empty)
                return result;
            nodeType* end = posBegin.node;
            nodeType* tmp = posBegin.parent_.lastChild;
//            while (!empty()) {
//                tmp = posSomeRoot.node;
//                popFront();
//            }
            posBegin.node = tmp;
            for ( ; posBegin.node != end; --posBegin)
                if ((result= dg(front())) != 0)
                    return result;
//            return result;
            return dg(front());
        }

        int opApplyReverse(int delegate(nodeType*, T) dg) {
            int result; /* continue as long as result==0 */
//            nodeType* node;
            if (empty)
                return result;
            nodeType* end = posBegin.node;
            nodeType* tmp = posBegin.parent_.lastChild;
//            while (!empty()) {
//                tmp = posSomeRoot.node;
//                popFront();
//            }
            posBegin.node = tmp;
            for ( ; posBegin.node != end; --posBegin)
                if ((result= dg(posBegin.node, front())) != 0)
                    return result;
//            return result;
            return dg(posBegin.node, front());
        }
    }

/*
        tree<T,tree_node_allocator>& operator=(const tree<T, tree_node_allocator>& other) {   // copy assignment
            if(this != &other)
                copy_(other);
            return *this;
        }
        tree<T,tree_node_allocator>& operator=(tree<T, tree_node_allocator>&& x) {        // move assignment
            if(this != &x) {
                head.nextSibling = x.head.nextSibling;
                feet.prevSibling = x.head.prevSibling;
                x.head.nextSibling.prevSibling = head;
                x.feet.prevSibling.nextSibling = feet;
                x.head.nextSibling = x.feet;
                x.feet.prevSibling = x.head;
            }
            return *this;
        }
*/

      /// Base class for iterators, only pointers stored, no traversal logic.
//#ifdef __SGI_STL_PORT
//        class iterator_base : public stlport::bidirectional_iterator<T, ptrdiff_t> {
//#else
        class iterator_base {
//#endif
/+
            public:
                alias T                               value_type;
                alias T*                              pointer;
                alias ref T                           reference;
                alias size_t                          size_type;
                alias ptrdiff_t                       difference_type;
////                alias std::bidirectional_iterator_tag iterator_category;

+/
                nodeType* node;
////            protected:
                bool skip_current_children_;

                this() { /*node = null; skip_current_children_ = false*/ }
                this(nodeType* tn) { node = tn; /*skip_current_children_ = false;*/ }
/+
                T&             operator*() const  { return node.data; }
                T*             operator.() const { return &(node.data); }
+/
            /// When called, the next increment/decrement skips children of this node.
//                void         skip_children()             { skip_current_children_ = true; }
                void         skip_children(bool skip=true) nothrow { skip_current_children_ = skip; }
                /// Number of children of the node pointed to by the iterator.
/+                uint number_of_children() const {
                    nodeType* pos = node.firstChild;
                    if (pos==null) return 0;

                    uint ret = 1;
                    while (pos!=node.lastChild) {
                        ++ret;
                        pos = pos.nextSibling;
                    }
                    return ret;
                }
+/
                sibling_iterator begin() /*const*/ nothrow {
                    if (node.firstChild == null)
                        return end();

                    auto ret = new sibling_iterator(this.node.firstChild);
                    ret.parent_ = this.node;
                    return ret;
                }
                sibling_iterator end() /*const*/ nothrow {
                    auto ret = new sibling_iterator(cast(nodeType*)null);
                    ret.parent_ = this.node;
                    return ret;
                }
        }

        /// Depth-first iterator, first accessing the node, then its children.
		/// Depth-first iterator, first accessing the node, then its children. Conform to Bidirectional Iterator Concept
		class pre_order_iterator : iterator_base {
            public:
                this()             { super(null); }
                this(nodeType* tn) { super(tn); }
                this(/*const ref*/ iterator_base other) { super(other.node); }

                this(/*const ref*/ sibling_iterator other) {
                    super(other.node);
                    if (this.node == null) {
                        if (other.range_last() != null)
                            this.node = other.range_last();
                        else
                            this.node = other.parent_;
                        this.skip_children();
                        ++this;
                    }
                }
/+
                bool    operator==(const pre_order_iterator& other) const {
                    if (other.node==this.node) return true;
                    else return false;
                }
                bool    operator!=(const pre_order_iterator& other) const {
                    if (other.node!=this.node) return true;
                    else return false;
                }
+/
                /*ref*/ pre_order_iterator opOpAssign(string op)(uint num)
                if (op == "+") {
                    while (num>0) {
//                        ++(*this);
                        assert(this.node != null);
                        if (!this.skip_current_children_ && this.node.firstChild != null) {
                            this.node = this.node.firstChild;
                        }
                        else {
                           this.skip_current_children_ = false;
                            while (this.node.nextSibling==null) {
                                this.node = this.node.parent;
                                if (this.node==null)
                                    return this;
                            }
                            this.node = this.node.nextSibling;
                        }
                        --num;
                    }
                    return this;
                }
                /*ref*/ pre_order_iterator opOpAssign(string op)(uint num)
                if (op == "-") {
                    while (num>0) {
//                        --(*this);
                        assert(this.node != null);
                        if (this.node.prevSibling) {
                            this.node = this.node.prevSibling;
                            while (this.node.lastChild)
                                this.node = this.node.lastChild;
                        }
                        else {
                            this.node = this.node.parent;
                            if (this.node==null)
                                return this;
                        }
                        --num;
                    }
                    return this;
                }
                bool opEquals(/*auto ref const*/const pre_order_iterator rhs) const nothrow {
                    if (rhs.node == this.node /*this.node is rhs.node || (this.node !is null && rhs.node !is null &&
                        this.node.parent      == rhs.node.parent &&
                        this.node.firstChild  == rhs.node.firstChild &&
                        this.node.lastChild   == rhs.node.lastChild &&
                        this.node.prevSibling == rhs.node.prevSibling &&
                        this.node.nextSibling == rhs.node.nextSibling )*/) return true;
                    else return false;
                }
                int opCmp(/*auto ref const*/const pre_order_iterator rhs) const {
                    if (this.opEquals(rhs))  return 0;
                    else return -1;
                }

                pre_order_iterator dup() /*const*/ nothrow {
                    return new pre_order_iterator(this.node);
                }

/+
                pre_order_iterator&  operator++() {
                    assert(this.node!=null);
                    if (!this.skip_current_children_ && this.node.firstChild != null) {
                        this.node = this.node.firstChild;
                    }
                    else {
                        this.skip_current_children_ = false;
                        while (this.node.nextSibling==null) {
                            this.node = this.node.parent;
                            if (this.node==null)
                                return *this;
                        }
                        this.node = this.node.nextSibling;
                    }
                    return *this;
                }
                pre_order_iterator&  operator--() {
                    assert(this.node!=null);
                    if (this.node.prevSibling) {
                        this.node = this.node.prevSibling;
                        while (this.node.lastChild)
                            this.node = this.node.lastChild;
                        }
                    else {
                        this.node = this.node.parent;
                        if (this.node==null)
                            return *this;
                    }
                    return *this;
                }
                pre_order_iterator   operator++(int) {
                    pre_order_iterator copy = *this;
                    ++(*this);
                    return copy;
                }

                pre_order_iterator   operator--(int) {
                    pre_order_iterator copy = *this;
                    --(*this);
                    return copy;
                }
                pre_order_iterator&  operator+=(uint num) {
                    while (num>0) {
                        ++(*this);
                        --num;
                    }
                    return (*this);
                }

                pre_order_iterator&  operator-=(uint num) {
                    while (num>0) {
                        --(*this);
                        --num;
                    }
                    return (*this);
                }

                pre_order_iterator&  next_skip_children() {
                    (*this).skip_children();
                    (*this)++;
                    return *this;
                }
+/
        }

        /// Depth-first iterator, first accessing the children, then the node itself.
        class post_order_iterator : iterator_base {
            public:
                this()             { super(null); }
                this(nodeType* tn) { super(tn); }
                this(/*const ref*/ iterator_base other) { super(other.node); }

                this(/*const ref*/ sibling_iterator other) {
                    super(other.node);
                    if (this.node == null) {
                        if (other.range_last() != null)
                            this.node = other.range_last();
                        else
                            this.node = other.parent_;
                        this.skip_children();
                        ++this;
                    }
                }

                bool opEquals(/*auto ref const*/const post_order_iterator rhs) const {
                    if (rhs.node == this.node) return true;
                    else return false;
                }
                int opCmp(/*auto ref const*/const post_order_iterator rhs) const {
                    if (this.opEquals(rhs))  return 0;
                    else return -1;
                }

                post_order_iterator dup() /*const*/ {
                    return new post_order_iterator(this.node);
                }
/+
                bool    operator!=(const post_order_iterator& other) const {
                    if (other.node!=this.node) return true;
                    else return false;
                }
                post_order_iterator&  operator++() {
                    assert(this.node!=null);
                    if (this.node.nextSibling==null) {
                        this.node = this.node.parent;
                        this.skip_current_children = false;
                    }
                    else {
                        this.node = this.node.nextSibling;
                        if (this.skip_current_children_) {
                            this.skip_current_children_= false;
                        }
                        else {
                            while (this.node.firstChild)
                                this.node = this.node.firstChild;
                        }
                    }
                    return *this;
                }
                post_order_iterator&  operator--() {
                    assert(this.node!=null);
                    if (this.skip_current_children_ || this.node.lastChild==null) {
                        this.skip_current_children_= false;
                        while (this.node.prevSibling==null)
                            this.node = this.node.parent;
                        this.node = this.node.prevSibling;
                    }
                    else {
                        this.node = this.node.lastChild;
                    }
                    return *this;
                }
                post_order_iterator   operator++(int) {
                    post_order_iterator copy = *this;
                    ++(*this);
                    return copy;
                }
                post_order_iterator   operator--(int) {
                    post_order_iterator copy = *this;
                    --(*this);
                    return copy;
                }+/
                /*ref*/ post_order_iterator opOpAssign(string op)(uint num)
                if (op == "+") {
                    while (num>0) {
//                        ++this;
                        assert(this.node != null);
                        if (this.node.nextSibling == null) {
                            this.node = this.node.parent;
////                            this.skip_current_children = false;
                        }
                        else {
                            this.node = this.node.nextSibling;
                            if (this.skip_current_children_)
                                this.skip_current_children_ = false;
                            else
                                while (this.node.firstChild)
                                    this.node = this.node.firstChild;
                        }
                        --num;
                    }
                    return this;
                }
                /*ref*/ post_order_iterator opOpAssign(string op)(uint num)
                if (op == "-") {
                    while (num>0) {
//                        --(*this);
                        assert(this.node != null);
                        if (this.skip_current_children_ || this.node.lastChild == null) {
                            this.skip_current_children_ = false;
                            while (this.node.prevSibling == null)
                                this.node = this.node.parent;
                            this.node = this.node.prevSibling;
                        }
                        else
                            this.node = this.node.lastChild;

                        --num;
                    }
                    return this;
                }

                /// Set iterator to the first child as deep as possible down the tree.
                void descend_all() {
                    assert(this.node != null);
                    while (this.node.firstChild)
                        this.node = this.node.firstChild;
                }
        }

        /// Breadth-first iterator, using a queue
        class breadth_first_queued_iterator : iterator_base {
//            import std.container.dlist : DList;
            import containers.cyclicbuffer : CyclicBuffer;
            public:
            this()             { super(null); }
            this(nodeType* tn) { super(tn); traversal_queue.insertBack(tn); }
            this(iterator_base other) { super(other.node); traversal_queue.insertBack(other.node); }
/+
                bool    operator==(const breadth_first_queued_iterator& other) const {
                    if (other.node==this.node) return true;
                    else return false;
                }
                bool    operator!=(const breadth_first_queued_iterator& other) const {
                    if (other.node!=this.node) return true;
                    else return false;
                }
+/
            /*ref*/ breadth_first_queued_iterator opOpAssign(string op)(uint num)
            if (op == "+") {
                    while (num>0) {


                        assert(this.node != null);

                        // Add child nodes and pop current node
                        sibling_iterator sib = this.begin();
                        while (sib != this.end()) {
                            traversal_queue.insertBack(sib.node);
                            ++sib;
                        }
                        traversal_queue.removeFront();
                        if (!traversal_queue.empty)
                            this.node = traversal_queue.front();
                        else
                            this.node = null;
//          return *this;
                        --num;
                    }
                    return this;
            }
/+
        breadth_first_queued_iterator   operator++(int) {
          breadth_first_queued_iterator copy = *this;
          ++(*this);
          return copy;
        }
        breadth_first_queued_iterator&  operator+=(uint num) {
          while (num>0) {
            ++(*this);
            --num;
          }
          return (*this);
        }

+/
            private:
            CyclicBuffer!(nodeType*, Alloc) traversal_queue;//DList!(nodeType*)  traversal_queue;//std::queue<nodeType*> traversal_queue;
        }

    /// The default iterator types throughout the tree class.
    alias iterator = pre_order_iterator;

    alias breadth_first_iterator = breadth_first_queued_iterator;
/+
    /// Iterator which traverses only the nodes at a given depth from the root.
    class fixed_depth_iterator : public iterator_base {
      public:
        fixed_depth_iterator() : iterator_base() {}
        fixed_depth_iterator(nodeType* tn) : iterator_base(tn), top_node(null) {}
        fixed_depth_iterator(const iterator_base& other) : iterator_base(other.node), top_node(null) {}
        fixed_depth_iterator(const sibling_iterator& other) : iterator_base(other.node), top_node(null) {}
        fixed_depth_iterator(const fixed_depth_iterator& other) : iterator_base(other.node), top_node(other.top_node) {}

        bool    operator==(const fixed_depth_iterator& other) const {
          if (other.node==this.node && other.top_node==top_node) return true;
          else return false;
        }
        bool    operator!=(const fixed_depth_iterator& other) const {
          if (other.node!=this.node || other.top_node!=top_node) return true;
          else return false;
        }
        fixed_depth_iterator&  operator++() {
          assert(this.node!=null);

          if (this.node.nextSibling) {
            this.node = this.node.nextSibling;
          }
          else {
            int relative_depth = 0;
            upper:
            do {
              if (this.node==this.top_node) {
                this.node = null; // FIXME: return a proper fixed_depth end iterator once implemented
                return *this;
              }
              this.node = this.node.parent;
              if (this.node==null) return *this;
              --relative_depth;
            } while(this.node.nextSibling==null);
            lower:
            this.node = this.node.nextSibling;
            while (this.node.firstChild==null) {
              if (this.node.nextSibling==null)
                goto upper;
              this.node = this.node.nextSibling;
              if (this.node==null) return *this;
            }
            while (relative_depth<0 && this.node.firstChild!=null) {
              this.node = this.node.firstChild;
              ++relative_depth;
            }
            if (relative_depth<0) {
              if(this.node.nextSibling==null) goto upper;
              else                          goto lower;
            }
          }
          return *this;
        }
        fixed_depth_iterator&  operator--() {
          assert(this.node!=null);

          if (this.node.prevSibling) {
            this.node = this.node.prevSibling;
          }
          else {
            int relative_depth = 0;
            upper:
            do {
              if (this.node==this.top_node) {
                this.node = null;
                return *this;
              }
              this.node = this.node.parent;
              if (this.node==null) return *this;
              --relative_depth;
            } while(this.node.prevSibling==null);
            lower:
            this.node=this.node.prevSibling;
            while (this.node.lastChild==null) {
              if (this.node.prevSibling==null)
                goto upper;
              this.node=this.node.prevSibling;
              if (this.node==null) return *this;
            }
            while (relative_depth<0 && this.node.lastChild!=null) {
              this.node=this.node.lastChild;
              ++relative_depth;
            }
            if (relative_depth<0) {
              if (this.node.prevSibling==null) goto upper;
              else                            goto lower;
            }
          }
          return *this;

        //
        //
        //  assert(this.node!=null);
        //  if(this.node.prevSibling!=null) {
        //    this.node=this.node.prevSibling;
        //    assert(this.node!=null);
        //    if(this.node.parent==null && this.node.prevSibling==null) // head element
        //      this.node=null;
        //    }
        //  else {
        //    nodeType* par=this.node.parent;
        //    do {
        //      par=par.prevSibling;
        //      if(par==null) { // FIXME: need to keep track of this!
        //        this.node=null;
        //        return *this;
        //        }
        //      } while(par.lastChild==null);
        //    this.node=par.lastChild;
        //    }
        //  return *this;
        }
        fixed_depth_iterator   operator++(int) {
          fixed_depth_iterator copy = *this;
          ++(*this);
          return copy;
        }
        fixed_depth_iterator   operator--(int) {
          fixed_depth_iterator copy = *this;
          --(*this);
          return copy;
        }
        fixed_depth_iterator&  operator+=(uint num) {
          while (num>0) {
            ++(*this);
            --(num);
          }
          return *this;
        }
        fixed_depth_iterator&  operator-=(uint num) {
          while (num>0) {
            --(*this);
            --(num);
          }
          return (*this);
        }

        nodeType* top_node;
    }
+/
    /// Iterator which traverses only the nodes which are siblings of each other.
    class sibling_iterator : iterator_base {
      public:
        nodeType* parent_;

        this()             { super();   set_parent_(); }
        this(nodeType* tn) { super(tn); set_parent_(); }
        this(/*const ref*/ sibling_iterator other) { super(other.node); /*iterator_base(other),*/ parent_ = other.parent_; }
        this(/*const ref*/ iterator_base other)    { super(other.node); set_parent_(); }

        bool opEquals(/*auto ref const*/const sibling_iterator rhs) const nothrow {
          if (rhs.node == this.node) return true;
          else return false;
        }
        sibling_iterator dup() /*const*/ nothrow {
            return new sibling_iterator(this.node);
        }
        /+
        bool    operator!=(const sibling_iterator& other) const {
          if (other.node!=this.node) return true;
          else return false;
        }
        sibling_iterator&  operator++() {
          if (this.node)
            this.node=this.node.nextSibling;
          return *this;
        }
        sibling_iterator&  operator--() {
          if (this.node) this.node=this.node.prevSibling;
          else {
            assert(parent_);
            this.node=parent_.lastChild;
          }
          return *this;
        }
        sibling_iterator   operator++(int) {
          sibling_iterator copy = *this;
          ++(*this);
          return copy;
        }
        sibling_iterator   operator--(int) {
          sibling_iterator copy = *this;
          --(*this);
          return copy;
        }+/
        /// Attention: "-" has "cycling" semantic
        /*ref*/ sibling_iterator opOpAssign(string op)(uint num)
        if ((op == "+") || (op == "-")) {
            while (num>0) {
                static if (op == "+") {
                    if (this.node)
                        this.node = this.node.nextSibling;
                }
                else { // op == "-"
                    if (this.node)
                        this.node = this.node.prevSibling;
                    else {
                        assert(parent_);
                        this.node = parent_.lastChild;
                    }
                }
                --num;
            }
            return this;
        }

        nodeType* range_first() /*const*/ { return parent_.firstChild; }
        nodeType* range_last()  /*const*/ { return parent_.lastChild; }
      private:
        void set_parent_() {
          parent_= null;
          if (this.node == null) return;
          if (this.node.parent != null)
            parent_ = this.node.parent;
        }
    }
/+
    /// Iterator which traverses only the leaves.
    class leaf_iterator : public iterator_base {
         public:
            leaf_iterator() : iterator_base(null), top_node(null) {}
            leaf_iterator(nodeType* tn, nodeType* top=null) : iterator_base(tn), top_node(top) {}
            leaf_iterator(const sibling_iterator& other) : iterator_base(other.node), top_node(null) {
               if(this.node==null) {
                  if(other.range_last()!=null)
                     this.node=other.range_last();
                  else
                     this.node=other.parent_;
                  ++(*this);
               }
            }
            leaf_iterator(const iterator_base& other)    : iterator_base(other.node), top_node(null) {}

            bool    operator==(const leaf_iterator& other) const {
               if(other.node==this.node && other.top_node==this.top_node) return true;
               else return false;
            }
            bool    operator!=(const leaf_iterator& other) const {
               if(other.node!=this.node) return true;
               else return false;
            }
            leaf_iterator&  operator++() {
              assert(this.node!=null);
              if(this.node.firstChild!=null) { // current node is no longer leaf (children got added)
                 while(this.node.firstChild)
                    this.node=this.node.firstChild;
              }
              else {
                 while(this.node.nextSibling==null) {
                    if (this.node.parent==null) return *this;
                    this.node=this.node.parent;
                    if (top_node != null && this.node==top_node) return *this;
                    }
                 this.node=this.node.nextSibling;
                 while(this.node.firstChild)
                    this.node=this.node.firstChild;
               }
              return *this;
            }
            leaf_iterator&  operator--() {
              assert(this.node!=null);
              while (this.node.prevSibling==null) {
                if (this.node.parent==null) return *this;
                this.node=this.node.parent;
                if (top_node !=null && this.node==top_node) return *this;
              }
              this.node=this.node.prevSibling;
              while(this.node.lastChild)
                this.node=this.node.lastChild;
              return *this;
            }
            leaf_iterator   operator++(int) {
               leaf_iterator copy = *this;
               ++(*this);
               return copy;
            }
            leaf_iterator   operator--(int) {
               leaf_iterator copy = *this;
               --(*this);
               return copy;
            }
            leaf_iterator&  operator+=(uint num) {
               while(num>0) {
                  ++(*this);
                  --num;
               }
               return (*this);
            }
            leaf_iterator&  operator-=(uint num) {
               while(num>0) {
                  --(*this);
                  --num;
               }
               return (*this);
            }
      private:
        nodeType* top_node;
      }
+/
    /// Return iterator to the beginning of the tree.
    /*inline*/ pre_order_iterator   begin() /*const*/ { return new pre_order_iterator(head.nextSibling); }
    /// Return iterator to the end of the tree.
    /*inline*/ pre_order_iterator   end()   /*const*/ { return new pre_order_iterator(feet); }
    /// Return post-order iterator to the beginning of the tree.
    post_order_iterator  begin_post() /*const*/ {
        nodeType* tmp = head.nextSibling;
        if (tmp != feet) {
            while (tmp.firstChild)
                tmp = tmp.firstChild;
        }
        return new post_order_iterator(tmp);
    }
    /// Return post-order end iterator of the tree.
    post_order_iterator  end_post() /*const*/ { return new post_order_iterator(feet); }/+
    /// Return fixed-depth iterator to the first node at a given depth from the given iterator.
    fixed_depth_iterator begin_fixed(const iterator_base& pos, uint dp) const {
      typename tree<T, tree_node_allocator>::fixed_depth_iterator ret;
      ret.top_node=pos.node;

      nodeType* tmp=pos.node;
      uint curdepth=0;
      while (curdepth<dp) { // go down one level
        while (tmp.firstChild==null) {
          if (tmp.nextSibling==null) {
            // try to walk up and then right again
            do {
              if (tmp==ret.top_node)
                throw std::range_error("tree: begin_fixed out of range");
              tmp=tmp.parent;
              if (tmp==null)
                throw std::range_error("tree: begin_fixed out of range");
              --curdepth;
            } while (tmp.nextSibling==null);
          }
          tmp=tmp.nextSibling;
        }
        tmp=tmp.firstChild;
        ++curdepth;
      }

      ret.node=tmp;
      return ret;
    }
    /// Return fixed-depth end iterator.
    fixed_depth_iterator end_fixed(const iterator_base& pos, uint dp) const {
      assert(1==0); // FIXME: not correct yet: use is_valid() as a temporary workaround
      nodeType* tmp=pos.node;
      uint curdepth=1;
      while (curdepth<dp) { // go down one level
        while (tmp.firstChild==null) {
          tmp=tmp.nextSibling;
          if (tmp==null)
            throw std::range_error("tree: end_fixed out of range");
        }
        tmp=tmp.firstChild;
        ++curdepth;
      }
      return tmp;
    }
    /// Return breadth-first iterator to the first node at a given depth.
    breadth_first_queued_iterator begin_breadth_first() const { return breadth_first_queued_iterator(head.nextSibling); }
    /// Return breadth-first end iterator.
    breadth_first_queued_iterator end_breadth_first()   const { return breadth_first_queued_iterator(); }
+/
    /// Return sibling iterator to the first child of given node.
    sibling_iterator     begin(/*const*/ iterator_base pos) /*const*/ {
      assert(pos.node != null);
      if (pos.node.firstChild == null) {
        return end(pos);
      }
      return new sibling_iterator(pos.node.firstChild);
    }
    /// Return sibling end iterator for children of given node.
    sibling_iterator     end(/*const*/ iterator_base pos) /*const*/ {
      sibling_iterator ret = new sibling_iterator(cast(nodeType*) null);
      ret.parent_ = pos.node;
      return ret;
    }
/+
    /// Return leaf iterator to the first leaf of the tree.
    leaf_iterator   begin_leaf() const {
      nodeType* tmp=head.nextSibling;
      if (tmp!=feet) {
        while (tmp.firstChild)
          tmp=tmp.firstChild;
      }
      return leaf_iterator(tmp);
    }
    /// Return leaf end iterator for entire tree.
    leaf_iterator   end_leaf() const { return leaf_iterator(feet); }
    /// Return leaf iterator to the first leaf of the subtree at the given node.
    leaf_iterator   begin_leaf(const iterator_base& top) const {
      nodeType* tmp=top.node;
      while (tmp.firstChild)
         tmp=tmp.firstChild;
      return leaf_iterator(tmp, top.node);
    }
    /// Return leaf end iterator for the subtree at the given node.
    leaf_iterator   end_leaf(const iterator_base& top) const { return leaf_iterator(top.node, top.node); }
+/
    /// Return iterator to the parent of a node.
    static Iter parent(Iter)(Iter position) {
        assert(position.node != null);
        return new Iter(position.node.parent);
    }

    static Iter first_child(Iter)(Iter position) {
        assert(position.node != null);
        return new Iter(position.node.firstChild);
    }
    static Iter last_child(Iter)(Iter position) {
        assert(position.node != null);
        return new Iter(position.node.lastChild);
    }

    /// Return iterator to the previous sibling of a node.
    static Iter previous_sibling(Iter)(Iter position) {
        assert(position.node != null);
//      auto ret = new Iter(position);
//      ret.node=position.node.prevSibling;
//      return ret;
        return new Iter(position.node.prevSibling);
    }
    /// Return iterator to the next sibling of a node.
    static Iter next_sibling(Iter)(Iter position) {
        assert(position.node != null);
//      auto ret = new Iter(position);
//      ret.node = position.node.nextSibling;
//      return ret;
        return new Iter(position.node.nextSibling);
    }
/+
    /// Return iterator to the next node at a given depth.
    template<typename iter> iter next_at_same_depth(iter position) const {
      // We make use of a temporary fixed_depth iterator to implement this.

      typename tree<T, tree_node_allocator>::fixed_depth_iterator tmp(position.node);

      ++tmp;
      return iter(tmp);

    //  assert(position.node!=null);
    //  iter ret(position);
    //
    //  if(position.node.nextSibling) {
    //    ret.node=position.node.nextSibling;
    //    }
    //  else {
    //    int relative_depth=0;
    //    upper:
    //    do {
    //      ret.node=ret.node.parent;
    //      if(ret.node==null) return ret;
    //      --relative_depth;
    //      } while(ret.node.nextSibling==null);
    //    lower:
    //    ret.node=ret.node.nextSibling;
    //    while(ret.node.firstChild==null) {
    //      if(ret.node.nextSibling==null)
    //        goto upper;
    //      ret.node=ret.node.nextSibling;
    //      if(ret.node==null) return ret;
    //      }
    //    while(relative_depth<0 && ret.node.firstChild!=null) {
    //      ret.node=ret.node.firstChild;
    //      ++relative_depth;
    //      }
    //    if(relative_depth<0) {
    //      if(ret.node.nextSibling==null) goto upper;
    //      else                                goto lower;
    //      }
    //    }
    //  return ret;
    }
+/
    /// Erase all nodes of the tree.
    void     clear() nothrow {
      if (head)
        while (head.nextSibling != feet)
          erase(new pre_order_iterator(head.nextSibling));
    }
    /// Erase element at position pointed to by iterator, return incremented iterator.
    Iter erase(Iter)(Iter it) nothrow {
        nodeType* cur = it.node;
        assert(cur);
        assert(cur != head);
        Iter ret = it.dup;
        ret.skip_children();
        ++ret;
        erase_children(it);
        if (cur.prevSibling == null)
          cur.parent.firstChild = cur.nextSibling;
        else
          cur.prevSibling.nextSibling = cur.nextSibling;
        if (cur.nextSibling == null)
          cur.parent.lastChild = cur.prevSibling;
        else
          cur.nextSibling.prevSibling = cur.prevSibling;

    //  kp::destructor(&cur.data);
        Alloc.instance.deallocate((cast(void*)cur)[0..nodeType.sizeof]);
//      alloc_.destroy(cur);
//      alloc_.deallocate(cur,1);
      return ret;
    }
    /// Erase all children of the node pointed to by iterator.
    void     erase_children(/*const ref*/ iterator_base it) nothrow {
    //  std::cout << "erase_children " << it.node << std::endl;
      if (it.node==null) return;

      nodeType* cur  = it.node.firstChild;
      nodeType* prev = null;

      while (cur != null) {
        prev = cur;
        cur  = cur.nextSibling;
//        auto new_pre_iter = new pre_order_iterator(prev);
        erase_children(new pre_order_iterator(prev));
    //    kp::destructor(&prev.data);
        Alloc.instance.deallocate((cast(void*)prev)[0..nodeType.sizeof]);
//        alloc_.destroy(prev);
//        alloc_.deallocate(prev,1);
      }
      it.node.firstChild = null;
      it.node.lastChild  = null;
    //  std::cout << "exit" << std::endl;
    }
/+
    /// Erase all siblings to the right of the iterator.
    void     erase_right_siblings(const iterator_base& it) {
      if (it.node==null) return;

      nodeType* cur=it.node.nextSibling;
      nodeType* prev=null;

      while (cur!=null) {
        prev=cur;
        cur=cur.nextSibling;
        erase_children(pre_order_iterator(prev));
    //    kp::destructor(&prev.data);
        alloc_.destroy(prev);
        alloc_.deallocate(prev,1);
      }
      it.node.nextSibling=null;
      if (it.node.parent!=null)
        it.node.parent.lastChild=it.node;
    }
    /// Erase all siblings to the left of the iterator.
    void     erase_left_siblings(const iterator_base& it) {
      if (it.node==null) return;

      nodeType* cur=it.node.prevSibling;
      nodeType* prev=null;

      while (cur!=null) {
        prev=cur;
        cur=cur.prevSibling;
        erase_children(pre_order_iterator(prev));
    //    kp::destructor(&prev.data);
        alloc_.destroy(prev);
        alloc_.deallocate(prev,1);
      }
      it.node.prevSibling=null;
      if (it.node.parent!=null)
        it.node.parent.firstChild=it.node;
    }
+/
    /// Insert empty node as last/first child of node pointed to by position.
    Iter append_child(Iter)(Iter position) {
        assert(position.node!=head);
        assert(position.node!=feet);
        assert(position.node);

        auto tmp = cast(nodeType*)Alloc.instance.allocate(nodeType.sizeof).ptr;
        emplace(&tmp.data, T.init);
//     alloc_.construct(tmp, tree_node_<T>());
    //  kp::constructor(&tmp.data);
      tmp.firstChild=null;
      tmp.lastChild=null;

      tmp.parent=position.node;
      if (position.node.lastChild!=null) {
        position.node.lastChild.nextSibling=tmp;
      }
      else {
        position.node.firstChild=tmp;
      }
      tmp.prevSibling=position.node.lastChild;
      position.node.lastChild=tmp;
      tmp.nextSibling=null;
      return tmp;
    }
    Iter prepend_child(Iter)(Iter position) {
        assert(position.node!=head);
        assert(position.node!=feet);
        assert(position.node);

        auto tmp = cast(nodeType*)Alloc.instance.allocate(nodeType.sizeof).ptr;
        emplace(&tmp.data, T.init);
//      alloc_.construct(tmp, tree_node_<T>());
    //  kp::constructor(&tmp.data);
        tmp.firstChild=null;
        tmp.lastChild=null;

        tmp.parent=position.node;
        if (position.node.firstChild != null)
            position.node.firstChild.prevSibling = tmp;

        else
            position.node.lastChild=tmp;

        tmp.nextSibling = position.node.firstChild;
        position.node.prev_child = tmp;
        tmp.prevSibling = null;
        return tmp;
    }
    /// Insert node as last/first child of node pointed to by position.
    Iter append_child(Iter)(Iter position, /*const*/ ref T x) {
      // If your program fails here you probably used 'append_child' to add the top
      // node to an empty tree. From version 1.45 the top element should be added
      // using 'insert'. See the documentation for further information, and sorry about
      // the API change.
        assert(position.node != head);
        assert(position.node != feet);
        assert(position.node);

        auto tmp = cast(nodeType*)Alloc.instance.allocate(nodeType.sizeof).ptr;
        emplace(&tmp.data, x.dup);
//      alloc_.construct(tmp, x);
    //  kp::constructor(&tmp.data, x);
      tmp.parent     = position.node;
      tmp.firstChild = null;
      tmp.lastChild  = null;

      if (position.node.lastChild != null)
        position.node.lastChild.nextSibling = tmp;
      else
        position.node.firstChild = tmp;
      tmp.prevSibling = position.node.lastChild;
      position.node.lastChild = tmp;
      tmp.nextSibling = null;
      return new Iter(tmp);
    }
/+
    template<typename Iter> Iter append_child(Iter position, T&& x) {
      assert(position.node!=head);
      assert(position.node!=feet);
      assert(position.node);

      auto tmp = cast(nodeType*)Alloc.instance.allocate(nodeType.sizeof).ptr;
      alloc_.construct(tmp); // Here is where the move semantics kick in
      std::swap(tmp.data, x);

      tmp.firstChild=null;
      tmp.lastChild=null;

      tmp.parent=position.node;
      if (position.node.lastChild!=null) {
        position.node.lastChild.nextSibling=tmp;
      }
      else {
        position.node.firstChild=tmp;
      }
      tmp.prevSibling=position.node.lastChild;
      position.node.lastChild=tmp;
      tmp.nextSibling=null;
      return tmp;
    }
+/
    Iter prepend_child(Iter)(Iter position, /*const*/ ref T x) {
        assert(position.node!=head);
        assert(position.node!=feet);
        assert(position.node);

        auto tmp = cast(nodeType*)Alloc.instance.allocate(nodeType.sizeof).ptr;
        emplace(&tmp.data, x.dup);
//      alloc_.construct(tmp, x);
    //  kp::constructor(&tmp.data, x);
      tmp.firstChild=null;
      tmp.lastChild=null;

      tmp.parent=position.node;
      if (position.node.firstChild!=null) {
        position.node.firstChild.prevSibling=tmp;
      }
      else {
        position.node.lastChild=tmp;
      }
      tmp.nextSibling=position.node.firstChild;
      position.node.firstChild=tmp;
      tmp.prevSibling=null;
      return tmp;
    }
/+
    template<typename Iter> Iter prepend_child(Iter position, T&& x) {
      assert(position.node!=head);
      assert(position.node!=feet);
      assert(position.node);

      auto tmp = cast(nodeType*)Alloc.instance.allocate(nodeType.sizeof).ptr;
      alloc_.construct(tmp);
      std::swap(tmp.data, x);

      tmp.firstChild=null;
      tmp.lastChild=null;

      tmp.parent=position.node;
      if (position.node.firstChild!=null) {
        position.node.firstChild.prevSibling=tmp;
      }
      else {
        position.node.lastChild=tmp;
      }
      tmp.nextSibling=position.node.firstChild;
      position.node.firstChild=tmp;
      tmp.prevSibling=null;
      return tmp;
    }

    /// Append the node (plus its children) at other_position as last/first child of position.
    template<typename Iter> Iter append_child(Iter position, Iter other_position) {
      assert(position.node!=head);
      assert(position.node!=feet);
      assert(position.node);

      sibling_iterator aargh=append_child(position, value_type());
      return replace(aargh, other_position);
    }
    template<typename Iter> Iter prepend_child(Iter position, Iter other_position) {
      assert(position.node!=head);
      assert(position.node!=feet);
      assert(position.node);

      sibling_iterator aargh=prepend_child(position, value_type());
      return replace(aargh, other_position);
    }
    /// Append the nodes in the from-to range (plus their children) as last/first children of position.
    template<typename Iter> Iter append_children(Iter position, sibling_iterator from, sibling_iterator to) {
      assert(position.node!=head);
      assert(position.node!=feet);
      assert(position.node);

      Iter ret=from;

      while (from!=to) {
        insert_subtree(position.end(), from);
        ++from;
      }
      return ret;
    }
    template<typename Iter> Iter prepend_children(Iter position, sibling_iterator from, sibling_iterator to) {
      assert(position.node!=head);
      assert(position.node!=feet);
      assert(position.node);

      Iter ret=from;

      while (from!=to) {
        insert_subtree(position.begin(), from);
        ++from;
      }
      return ret;
    }
+/
    /// Short-hand to insert topmost node in otherwise empty tree.
    pre_order_iterator set_head(/*const*/ ref T x) {
      assert(head.nextSibling == feet);
      return insert(new iterator(feet), x);
    }
/+
    pre_order_iterator set_head(T&& x) {
      assert(head.nextSibling==feet);
      return insert(iterator(feet), x);
    }
+/
    /// Insert node as previous sibling of node pointed to by position.
    Iter insert(Iter)(Iter position, /*const*/ ref T x) {
        if (position.node == null)
            position.node = feet; // Backward compatibility: when calling insert on a null node,
                                  // insert before the feet.

        assert(position.node != head); // Cannot insert before head.

        auto tmp = cast(nodeType*)Alloc.instance.allocate(nodeType.sizeof).ptr;
        emplace(&tmp.data, x.dup);
//      alloc_.construct(tmp, x);
    //  kp::constructor(&tmp.data, x);
        tmp.firstChild = null;
        tmp.lastChild = null;

        tmp.parent = position.node.parent;
        tmp.nextSibling = position.node;
        tmp.prevSibling = position.node.prevSibling;
        position.node.prevSibling = tmp;

        if (tmp.prevSibling != null)
            tmp.prevSibling.nextSibling = tmp;
        else
            if (tmp.parent) // when inserting nodes at the head, there is no parent
                tmp.parent.firstChild = tmp;
        return new Iter(tmp);
    }
/+
    template<typename Iter> Iter insert(Iter position, T&& x) {
      if (position.node==null) {
        position.node=feet; // Backward compatibility: when calling insert on a null node,
                            // insert before the feet.
      }
      nodeType* tmp = alloc_.allocate(1,0);
      alloc_.construct(tmp);
      std::swap(tmp.data, x); // Move semantics
      tmp.firstChild=null;
      tmp.lastChild=null;

      tmp.parent=position.node.parent;
      tmp.nextSibling=position.node;
      tmp.prevSibling=position.node.prevSibling;
      position.node.prevSibling=tmp;

      if (tmp.prevSibling==null) {
        if (tmp.parent) // when inserting nodes at the head, there is no parent
          tmp.parent.firstChild=tmp;
      }
      else
        tmp.prevSibling.nextSibling=tmp;
      return tmp;
    }
+/
    /// Specialisation of previous member.
    sibling_iterator insert(sibling_iterator position, /*const*/ ref T x) {
        auto tmp = cast(nodeType*)Alloc.instance.allocate(nodeType.sizeof).ptr;
        emplace(&tmp.data, x.dup);
//      alloc_.construct(tmp, x);
    //  kp::constructor(&tmp.data, x);
      tmp.firstChild=null;
      tmp.lastChild=null;

      tmp.nextSibling=position.node;
      if (position.node==null) { // iterator points to end of a subtree
        tmp.parent=position.parent_;
        tmp.prevSibling=position.range_last();
        tmp.parent.lastChild=tmp;
      }
      else {
        tmp.parent=position.node.parent;
        tmp.prevSibling=position.node.prevSibling;
        position.node.prevSibling=tmp;
      }

      if (tmp.prevSibling==null) {
        if (tmp.parent) // when inserting nodes at the head, there is no parent
          tmp.parent.firstChild=tmp;
      }
      else
        tmp.prevSibling.nextSibling=tmp;
      return new sibling_iterator(tmp);
    }/+
    /// Insert node (with children) pointed to by subtree as previous sibling of node pointed to by position.
    /// Does not change the subtree itself (use move_in or move_in_below for that).
    template<typename Iter> Iter insert_subtree(Iter position, const iterator_base& subtree) {
      // insert dummy
      Iter it=insert(position, value_type());
      // replace dummy with subtree
      return replace(it, subtree);
    }+/
    /// Insert node as next sibling of node pointed to by position.
    Iter insert_after(Iter)(Iter position, /*const*/ ref T x) {
        auto tmp = cast(nodeType*)Alloc.instance.allocate(nodeType.sizeof).ptr;
        emplace(&tmp.data, x.dup);
//      alloc_.construct(tmp, x);
    //  kp::constructor(&tmp.data, x);
        tmp.parent      = position.node.parent;
        tmp.firstChild  = null;
        tmp.lastChild   = null;
        tmp.prevSibling = position.node;
        tmp.nextSibling = position.node.nextSibling;
        position.node.nextSibling = tmp;

        if (tmp.nextSibling != null)
          tmp.nextSibling.prevSibling=tmp;
        else
          if (tmp.parent) // when inserting nodes at the head, there is no parent
            tmp.parent.lastChild = tmp;
        return new Iter(tmp);
    }/+
    template<typename Iter> Iter insert_after(Iter position, T&& x) {
      nodeType* tmp = alloc_.allocate(1,0);
      alloc_.construct(tmp);
      std::swap(tmp.data, x); // move semantics
    //  kp::constructor(&tmp.data, x);
      tmp.firstChild=null;
      tmp.lastChild=null;

      tmp.parent=position.node.parent;
      tmp.prevSibling=position.node;
      tmp.nextSibling=position.node.nextSibling;
      position.node.nextSibling=tmp;

      if (tmp.nextSibling==null) {
        if (tmp.parent) // when inserting nodes at the head, there is no parent
          tmp.parent.lastChild=tmp;
      }
      else {
        tmp.nextSibling.prevSibling=tmp;
      }
      return tmp;
    }
    /// Insert node (with children) pointed to by subtree as next sibling of node pointed to by position.
    template<typename Iter> Iter insert_subtree_after(Iter position, const iterator_base& subtree) {
      // insert dummy
      Iter it=insert_after(position, value_type());
      // replace dummy with subtree
      return replace(it, subtree);
    }

    /// Replace node at 'position' with other node (keeping same children); 'position' becomes invalid.
    template<typename Iter> Iter replace(Iter position, const T& x) {
    //  kp::destructor(&position.node.data);
    //  kp::constructor(&position.node.data, x);
      position.node.data=x;
    //  alloc_.destroy(position.node);
    //  alloc_.construct(position.node, x);
      return position;
    }
    /// Replace node at 'position' with subtree starting at 'from' (do not erase subtree at 'from'); see above.
    template<typename Iter> Iter replace(Iter position, const iterator_base& from) {
      assert(position.node!=head);
      nodeType* current_from=from.node;
      nodeType* start_from=from.node;
      nodeType* current_to  =position.node;

      // replace the node at position with head of the replacement tree at from
    //  std::cout << "warning!" << position.node << std::endl;
      erase_children(position);
    //  std::cout << "no warning!" << std::endl;
      nodeType* tmp = alloc_.allocate(1,0);
      alloc_.construct(tmp, (*from));
    //  kp::constructor(&tmp.data, (*from));
      tmp.firstChild=null;
      tmp.lastChild=null;
      if (current_to.prevSibling==null) {
        if (current_to.parent!=null)
          current_to.parent.firstChild=tmp;
      }
      else {
        current_to.prevSibling.nextSibling=tmp;
      }
      tmp.prevSibling=current_to.prevSibling;
      if (current_to.nextSibling==null) {
        if (current_to.parent!=null)
          current_to.parent.lastChild=tmp;
      }
      else {
        current_to.nextSibling.prevSibling=tmp;
      }
      tmp.nextSibling=current_to.nextSibling;
      tmp.parent=current_to.parent;
    //  kp::destructor(&current_to.data);
      alloc_.destroy(current_to);
      alloc_.deallocate(current_to,1);
      current_to=tmp;

      // only at this stage can we fix 'last'
      nodeType* last=from.node.nextSibling;

      pre_order_iterator toit=tmp;
      // copy all children
      do {
        assert(current_from!=null);
        if (current_from.firstChild != null) {
          current_from=current_from.firstChild;
          toit=append_child(toit, current_from.data);
        }
        else {
          while (current_from.nextSibling==null && current_from!=start_from) {
            current_from=current_from.parent;
            toit=parent(toit);
            assert(current_from!=null);
          }
          current_from=current_from.nextSibling;
          if (current_from!=last) {
            toit=append_child(parent(toit), current_from.data);
          }
        }
      } while(current_from!=last);

      return current_to;
    }
    /// Replace string of siblings (plus their children) with copy of a new string (with children); see above
    sibling_iterator replace(sibling_iterator orig_begin, sibling_iterator orig_end,
                     sibling_iterator new_begin,  sibling_iterator new_end) {
      nodeType* orig_first=orig_begin.node;
      nodeType* new_first=new_begin.node;
      nodeType* orig_last=orig_first;
      while ((++orig_begin)!=orig_end)
        orig_last=orig_last.nextSibling;
      nodeType* new_last=new_first;
      while ((++new_begin)!=new_end)
        new_last=new_last.nextSibling;

      // insert all siblings in new_first..new_last before orig_first
      bool first=true;
      pre_order_iterator ret;
      while (1==1) {
        pre_order_iterator tt=insert_subtree(pre_order_iterator(orig_first), pre_order_iterator(new_first));
        if (first) {
          ret=tt;
          first=false;
        }
        if (new_first==new_last)
          break;
        new_first=new_first.nextSibling;
      }

      // erase old range of siblings
      bool last=false;
      nodeType* next=orig_first;
      while (1==1) {
        if(next==orig_last)
          last=true;
        next=next.nextSibling;
        erase((pre_order_iterator)orig_first);
        if (last)
          break;
        orig_first=next;
      }
      return ret;
    }

    /// Move all children of node at 'position' to be siblings, returns position.
    template<typename Iter> Iter flatten(Iter position) {
      if(position.node.firstChild==null)
        return position;

      nodeType* tmp=position.node.firstChild;
      while (tmp) {
        tmp.parent=position.node.parent;
        tmp=tmp.nextSibling;
      }
      if (position.node.nextSibling) {
        position.node.lastChild.nextSibling=position.node.nextSibling;
        position.node.nextSibling.prevSibling=position.node.lastChild;
      }
      else {
        position.node.parent.lastChild=position.node.lastChild;
      }
      position.node.nextSibling=position.node.firstChild;
      position.node.nextSibling.prevSibling=position.node;
      position.node.firstChild=null;
      position.node.lastChild=null;

      return position;
    }
    /// Move nodes in range to be children of 'position'.
    template<typename Iter> Iter reparent(Iter position, sibling_iterator begin, sibling_iterator end) {
      nodeType* first=begin.node;
      nodeType* last=first;

      assert(first!=position.node);

      if (begin==end) return begin;
      // determine last node
      while ((++begin)!=end) {
        last=last.nextSibling;
      }
      // move subtree
      if (first.prevSibling==null) {
        first.parent.firstChild=last.nextSibling;
      }
      else {
        first.prevSibling.nextSibling=last.nextSibling;
      }
      if (last.nextSibling==null) {
        last.parent.lastChild=first.prevSibling;
      }
      else {
        last.nextSibling.prevSibling=first.prevSibling;
      }
      if (position.node.firstChild==null) {
        position.node.firstChild=first;
        position.node.lastChild=last;
        first.prevSibling=null;
      }
      else {
        position.node.lastChild.nextSibling=first;
        first.prevSibling=position.node.lastChild;
        position.node.lastChild=last;
      }
      last.nextSibling=null;

      nodeType* pos=first;
      for(;;) {
        pos.parent=position.node;
        if(pos==last) break;
        pos=pos.nextSibling;
      }

      return first;
    }
    /// Move all child nodes of 'from' to be children of 'position'.
    template<typename Iter> Iter reparent(Iter position, Iter from) {
      if (from.node.firstChild==null) return position;
      return reparent(position, from.node.firstChild, end(from));
    }

    /// Replace node with a new node, making the old node a child of the new node.
    template<typename Iter> Iter wrap(Iter position, const T& x) {
      assert(position.node!=null);
      sibling_iterator fr=position, to=position;
      ++to;
      Iter ret = insert(position, x);
      reparent(ret, fr, to);
      return ret;
    }

    /// Move 'source' node (plus its children) to become the next sibling of 'target'.
    template<typename Iter> Iter move_after(Iter target, Iter source) {
      nodeType* dst=target.node;
      nodeType* src=source.node;
      assert(dst);
      assert(src);

      if (dst==src) return source;
      if (dst.nextSibling)
        if (dst.nextSibling==src) // already in the right spot
          return source;

      // take src out of the tree
      if (src.prevSibling!=null) src.prevSibling.nextSibling=src.nextSibling;
      else                     src.parent.firstChild=src.nextSibling;
      if (src.nextSibling!=null) src.nextSibling.prevSibling=src.prevSibling;
      else                     src.parent.lastChild=src.prevSibling;

      // connect it to the new point
      if (dst.nextSibling!=null) dst.nextSibling.prevSibling=src;
      else                     dst.parent.lastChild=src;
      src.nextSibling=dst.nextSibling;
      dst.nextSibling=src;
      src.prevSibling=dst;
      src.parent=dst.parent;
      return src;
    }
    /// Move 'source' node (plus its children) to become the previous sibling of 'target'.
    template<typename Iter> Iter move_before(Iter target, Iter source) {
      nodeType* dst=target.node;
      nodeType* src=source.node;
      assert(dst);
      assert(src);

      if (dst==src) return source;
      if (dst.prevSibling)
        if (dst.prevSibling==src) // already in the right spot
          return source;

      // take src out of the tree
      if (src.prevSibling!=null) src.prevSibling.nextSibling=src.nextSibling;
      else                     src.parent.firstChild=src.nextSibling;
      if (src.nextSibling!=null) src.nextSibling.prevSibling=src.prevSibling;
      else                     src.parent.lastChild=src.prevSibling;

      // connect it to the new point
      if (dst.prevSibling!=null) dst.prevSibling.nextSibling=src;
      else                     dst.parent.firstChild=src;
      src.prevSibling=dst.prevSibling;
      dst.prevSibling=src;
      src.nextSibling=dst;
      src.parent=dst.parent;
      return src;
    }
    template<typename Iter> Iter move_ontop(Iter target, Iter source) {
      nodeType* dst=target.node;
      nodeType* src=source.node;
      assert(dst);
      assert(src);

      if (dst==src) return source;

    //  if(dst==src.prevSibling) {
    //
    //    }

      // remember connection points
      nodeType* b_prev_sibling=dst.prevSibling;
      nodeType* b_next_sibling=dst.nextSibling;
      nodeType* b_parent=dst.parent;

      // remove target
      erase(target);

      // take src out of the tree
      if (src.prevSibling!=null) src.prevSibling.nextSibling=src.nextSibling;
      else                            src.parent.firstChild=src.nextSibling;
      if (src.nextSibling!=null) src.nextSibling.prevSibling=src.prevSibling;
      else                            src.parent.lastChild=src.prevSibling;

      // connect it to the new point
      if (b_prev_sibling!=null) b_prev_sibling.nextSibling=src;
      else                         b_parent.firstChild=src;
      if (b_next_sibling!=null) b_next_sibling.prevSibling=src;
      else                         b_parent.lastChild=src;
      src.prevSibling=b_prev_sibling;
      src.nextSibling=b_next_sibling;
      src.parent=b_parent;
      return src;
    }
    sibling_iterator move_before(sibling_iterator target, sibling_iterator source) {
      nodeType* dst=target.node;
      nodeType* src=source.node;
      nodeType* dst_prev_sibling;
      if (dst==null) { // must then be an end iterator
        dst_prev_sibling=target.parent_.lastChild;
        assert(dst_prev_sibling);
      }
      else dst_prev_sibling=dst.prevSibling;
      assert(src);

      if (dst==src) return source;
      if (dst_prev_sibling)
        if (dst_prev_sibling==src) // already in the right spot
          return source;

      // take src out of the tree
      if (src.prevSibling!=null) src.prevSibling.nextSibling=src.nextSibling;
      else                            src.parent.firstChild=src.nextSibling;
      if (src.nextSibling!=null) src.nextSibling.prevSibling=src.prevSibling;
      else                            src.parent.lastChild=src.prevSibling;

      // connect it to the new point
      if (dst_prev_sibling!=null) dst_prev_sibling.nextSibling=src;
      else                           target.parent_.firstChild=src;
      src.prevSibling=dst_prev_sibling;
      if (dst) {
        dst.prevSibling=src;
        src.parent=dst.parent;
      }
      src.nextSibling=dst;
      return src;
    }
    /// Move 'source' node (plus its children) to become the node at 'target' (erasing the node at 'target').
    template<typename Iter> Iter move_ontop(Iter target, Iter source) {
      nodeType* dst=target.node;
      nodeType* src=source.node;
      assert(dst);
      assert(src);

      if (dst==src) return source;

    //  if(dst==src.prevSibling) {
    //
    //    }

      // remember connection points
      nodeType* b_prev_sibling=dst.prevSibling;
      nodeType* b_next_sibling=dst.nextSibling;
      nodeType* b_parent=dst.parent;

      // remove target
      erase(target);

      // take src out of the tree
      if (src.prevSibling!=null) src.prevSibling.nextSibling=src.nextSibling;
      else                            src.parent.firstChild=src.nextSibling;
      if (src.nextSibling!=null) src.nextSibling.prevSibling=src.prevSibling;
      else                            src.parent.lastChild=src.prevSibling;

      // connect it to the new point
      if (b_prev_sibling!=null) b_prev_sibling.nextSibling=src;
      else                         b_parent.firstChild=src;
      if (b_next_sibling!=null) b_next_sibling.prevSibling=src;
      else                         b_parent.lastChild=src;
      src.prevSibling=b_prev_sibling;
      src.nextSibling=b_next_sibling;
      src.parent=b_parent;
      return src;
    }

    /// Extract the subtree starting at the indicated node, removing it from the original tree.
    tree                         move_out(iterator source) {
      tree ret;

      // Move source node into the 'ret' tree.
      ret.head.nextSibling = source.node;
      ret.feet.prevSibling = source.node;
      source.node.parent=null;

      // Close the links in the current tree.
      if (source.node.prevSibling!=null)
        source.node.prevSibling.nextSibling = source.node.nextSibling;

      if (source.node.nextSibling!=null)
        source.node.nextSibling.prevSibling = source.node.prevSibling;

      // Fix source prev/next links.
      source.node.prevSibling = ret.head;
      source.node.nextSibling = ret.feet;

      return ret; // A good compiler will move this, not copy.
    }
    /// Inverse of take_out: inserts the given tree as previous sibling of indicated node by a
    /// move operation, that is, the given tree becomes empty. Returns iterator to the top node.
    template<typename Iter> Iter move_in(Iter loc, tree& other) {
      if (other.head.nextSibling==other.feet) return loc; // other tree is empty

      nodeType* other_first_head = other.head.nextSibling;
      nodeType* other_last_head  = other.feet.prevSibling;

      sibling_iterator prev(loc);
      --prev;

      prev.node.nextSibling = other_first_head;
      loc.node.prevSibling  = other_last_head;
      other_first_head.prevSibling = prev.node;
      other_last_head.nextSibling  = loc.node;

      // Adjust parent pointers.
      nodeType* walk=other_first_head;
      while (true) {
        walk.parent=loc.node.parent;
        if (walk==other_last_head)
          break;
        walk=walk.nextSibling;
      }

      // Close other tree.
      other.head.nextSibling=other.feet;
      other.feet.prevSibling=other.head;

      return other_first_head;
    }
    /// As above, but now make the tree a child of the indicated node.
    template<typename Iter> Iter move_in_below(Iter, tree&);
    /// As above, but now make the tree the nth child of the indicated node (if possible).
    template<typename Iter> Iter move_in_as_nth_child(Iter loc, size_t n, tree& other) {
      if(other.head.nextSibling==other.feet) return loc; // other tree is empty

      nodeType* other_first_head = other.head.nextSibling;
      nodeType* other_last_head  = other.feet.prevSibling;

      if (n==0) {
        if (loc.node.firstChild==null) {
          loc.node.firstChild=other_first_head;
          loc.node.lastChild=other_last_head;
          other_last_head.nextSibling=null;
          other_first_head.prevSibling=null;
        }
        else {
          loc.node.firstChild.prevSibling=other_last_head;
          other_last_head.nextSibling=loc.node.firstChild;
          loc.node.firstChild=other_first_head;
          other_first_head.prevSibling=null;
        }
      }
      else {
        --n;
        nodeType* walk = loc.node.firstChild;
        while (true) {
          if (walk==null)
            throw std::range_error("tree: move_in_as_nth_child position out of range");
          if (n==0)
            break;
          --n;
          walk = walk.nextSibling;
        }
        if (walk.nextSibling==null)
          loc.node.lastChild=other_last_head;
        else
          walk.nextSibling.prevSibling=other_last_head;
        other_last_head.nextSibling=walk.nextSibling;
        walk.nextSibling=other_first_head;
        other_first_head.prevSibling=walk;
      }

      // Adjust parent pointers.
      nodeType* walk=other_first_head;
      while (true) {
        walk.parent=loc.node;
        if (walk==other_last_head)
          break;
        walk=walk.nextSibling;
      }

      // Close other tree.
      other.head.nextSibling=other.feet;
      other.feet.prevSibling=other.head;

      return other_first_head;
    }

    /// Merge with other tree, creating new branches and leaves only if they are not already present.
    void     merge(sibling_iterator to1,   sibling_iterator to2, sibling_iterator from1, sibling_iterator from2,
              bool duplicate_leaves=false) {
      sibling_iterator fnd;
      while (from1!=from2) {
        if ((fnd=std::find(to1, to2, (*from1))) != to2) { // element found
          if (from1.begin()==from1.end()) { // full depth reached
            if (duplicate_leaves)
              append_child(parent(to1), (*from1));
          }
          else { // descend further
            merge(fnd.begin(), fnd.end(), from1.begin(), from1.end(), duplicate_leaves);
          }
        }
        else { // element missing
          insert_subtree(to2, from1);
        }
        ++from1;
      }
    }
    /// Sort (std::sort only moves values of nodes, this one moves children as well).
    void     sort(sibling_iterator from, sibling_iterator to, bool deep=false) {
      std::less<T> comp;
      sort(from, to, comp, deep);
    }
    template<class StrictWeakOrdering>
    void     sort(sibling_iterator from, sibling_iterator to, StrictWeakOrdering comp, bool deep=false) {
      if (from==to) return;
      // make list of sorted nodes
      // CHECK: if multiset stores equivalent nodes in the order in which they
      // are inserted, then this routine should be called 'stable_sort'.
      std::multiset<nodeType*, compare_nodes<StrictWeakOrdering> > nodes(comp);
      sibling_iterator it=from, it2=to;
      while (it != to) {
        nodes.insert(it.node);
        ++it;
      }
      // reassemble
      --it2;

      // prev and next are the nodes before and after the sorted range
      nodeType* prev=from.node.prevSibling;
      nodeType* next=it2.node.nextSibling;
      typename std::multiset<nodeType*, compare_nodes<StrictWeakOrdering> >::iterator nit=nodes.begin(), eit=nodes.end();
      if (prev==null) {
        if ((*nit).parent!=null) // to catch "sorting the head" situations, when there is no parent
          (*nit).parent.firstChild=(*nit);
      }
      else prev.nextSibling=(*nit);

      --eit;
      while (nit!=eit) {
        (*nit).prevSibling=prev;
        if (prev)
          prev.nextSibling=(*nit);
        prev=(*nit);
        ++nit;
      }
      // prev now points to the last-but-one node in the sorted range
      if (prev)
        prev.nextSibling=(*eit);

      // eit points to the last node in the sorted range.
      (*eit).nextSibling=next;
      (*eit).prevSibling=prev; // missed in the loop above
      if (next==null) {
        if ((*eit).parent!=null) // to catch "sorting the head" situations, when there is no parent
          (*eit).parent.lastChild=(*eit);
        }
      else next.prevSibling=(*eit);

      if (deep) {  // sort the children of each node too
        sibling_iterator bcs(*nodes.begin());
        sibling_iterator ecs(*eit);
        ++ecs;
        while (bcs!=ecs) {
          sort(begin(bcs), end(bcs), comp, deep);
          ++bcs;
        }
      }
    }
    /// Compare two ranges of nodes (compares nodes as well as tree structure).
    template<typename Iter>
    bool     equal(const Iter& one, const Iter& two, const Iter& three) const {
      std::equal_to<T> comp;
      return equal(one, two, three, comp);
    }
    template<typename Iter, class BinaryPredicate>
    bool     equal(const Iter& one, const Iter& two, const Iter& three, BinaryPredicate fun) const {
      pre_order_iterator one_(one), three_(three);

    //  if(one_==two && is_valid(three_) && three_.number_of_children()!=0)
    //    return false;
      while (one_!=two && is_valid(three_)) {
        if (!fun(*one_,*three_))
          return false;
        if (one_.number_of_children()!=three_.number_of_children())
          return false;
        ++one_;
        ++three_;
      }
      return true;
    }
    template<typename Iter>
    bool     equal_subtree(const Iter& one, const Iter& two) const {
      std::equal_to<T> comp;
      return equal_subtree(one, two, comp);
    }
    template<typename Iter, class BinaryPredicate>
    bool     equal_subtree(const Iter& one, const Iter& two, BinaryPredicate fun) const {
      pre_order_iterator one_(one), two_(two);

      if (!fun(*one_,*two_)) return false;
      if (number_of_children(one_)!=number_of_children(two_)) return false;
      return equal(begin(one_),end(one_),begin(two_),fun);
    }
    /// Extract a new tree formed by the range of siblings plus all their children.
    tree     subtree(sibling_iterator from, sibling_iterator to) const {
      assert(from!=to); // if from==to, the range is empty, hence no tree to return.

      tree tmp;
      tmp.set_head(value_type());
      tmp.replace(tmp.begin(), tmp.end(), from, to);
      return tmp;
    }
    void     subtree(tree& tmp, sibling_iterator from, sibling_iterator to) const {
      assert(from!=to); // if from==to, the range is empty, hence no tree to return.

      tmp.set_head(value_type());
      tmp.replace(tmp.begin(), tmp.end(), from, to);
    }
    /// Exchange the node (plus subtree) with its sibling node (do nothing if no sibling present).
    void     swap(sibling_iterator it) {
      nodeType* nxt=it.node.nextSibling;
      if (nxt) {
        if (it.node.prevSibling)
          it.node.prevSibling.nextSibling=nxt;
        else
          it.node.parent.firstChild=nxt;
        nxt.prevSibling=it.node.prevSibling;
        nodeType* nxtnxt=nxt.nextSibling;
        if (nxtnxt)
          nxtnxt.prevSibling=it.node;
        else
          it.node.parent.lastChild=it.node;
        nxt.nextSibling=it.node;
        it.node.prevSibling=nxt;
        it.node.nextSibling=nxtnxt;
      }
    }
    /// Exchange two nodes (plus subtrees)
    void     swap(iterator one, iterator two) {
      // if one and two are adjacent siblings, use the sibling swap
      if (one.node.nextSibling==two.node) swap(one);
      else if (two.node.nextSibling==one.node) swap(two);
      else {
        nodeType* nxt1=one.node.nextSibling;
        nodeType* nxt2=two.node.nextSibling;
        nodeType* pre1=one.node.prevSibling;
        nodeType* pre2=two.node.prevSibling;
        nodeType* par1=one.node.parent;
        nodeType* par2=two.node.parent;

        // reconnect
        one.node.parent=par2;
        one.node.nextSibling=nxt2;
        if (nxt2) nxt2.prevSibling=one.node;
        else      par2.lastChild=one.node;
        one.node.prevSibling=pre2;
        if (pre2) pre2.nextSibling=one.node;
        else      par2.firstChild=one.node;

        two.node.parent=par1;
        two.node.nextSibling=nxt1;
        if (nxt1) nxt1.prevSibling=two.node;
        else      par1.lastChild=two.node;
        two.node.prevSibling=pre1;
        if (pre1) pre1.nextSibling=two.node;
        else      par1.firstChild=two.node;
      }
    }

    /// Count the total number of nodes.
    size_t   size() const {
      size_t i=0;
      pre_order_iterator it=begin(), eit=end();
      while (it!=eit) {
        ++i;
        ++it;
      }
      return i;
    }
    /// Count the total number of nodes below the indicated node (plus one).
    size_t   size(const iterator_base& top) const {
      size_t i=0;
      pre_order_iterator it=top, eit=top;
      eit.skip_children();
      ++eit;
      while (it!=eit) {
        ++i;
        ++it;
      }
      return i;
    }
    /// Check if tree is empty.
    bool     empty() const {
      pre_order_iterator it=begin(), eit=end();
      return (it==eit);
    }
    /// Compute the depth to the root or to a fixed other iterator.
    static int depth(const iterator_base& it) {
      nodeType* pos=it.node;
      assert(pos!=null);
      int ret=0;
      while (pos.parent!=null) {
        pos=pos.parent;
        ++ret;
      }
      return ret;
    }
    static int depth(const iterator_base& it, const iterator_base& root) {
      nodeType* pos=it.node;
      assert(pos!=null);
      int ret=0;
      while (pos.parent!=null && pos!=root.node) {
        pos=pos.parent;
        ++ret;
      }
      return ret;
    }
    /// Determine the maximal depth of the tree. An empty tree has max_depth=-1.
    int      max_depth() const {
      int maxd=-1;
      for (nodeType* it = head.nextSibling; it!=feet; it=it.nextSibling)
        maxd=std::max(maxd, max_depth(it));

      return maxd;
    }
    /// Determine the maximal depth of the tree with top node at the given position.
    int      max_depth(const iterator_base& pos) const {
      nodeType* tmp=pos.node;

      if (tmp==null || tmp==head || tmp==feet) return -1;

      int curdepth=0, maxdepth=0;
      while (true) { // try to walk the bottom of the tree
        while (tmp.firstChild==null) {
          if (tmp==pos.node) return maxdepth;
          if (tmp.nextSibling==null) {
            // try to walk up and then right again
            do {
              tmp=tmp.parent;
              if(tmp==null) return maxdepth;
              --curdepth;
            } while(tmp.nextSibling==null);
          }
          if(tmp==pos.node) return maxdepth;
          tmp=tmp.nextSibling;
        }
        tmp=tmp.firstChild;
        ++curdepth;
        maxdepth=std::max(curdepth, maxdepth);
      }
    }
    /// Count the number of children of node at position.
    static uint number_of_children(const iterator_base& it) {
      nodeType* pos=it.node.firstChild;
      if (pos==null) return 0;

      uint ret=1;
    //    while (pos!=it.node.lastChild) {
    //      ++ret;
    //      pos=pos.nextSibling;
    //    }
      while ((pos=pos.nextSibling))
        ++ret;
      return ret;
    }
    /// Count the number of siblings (left and right) of node at iterator. Total nodes at this level is +1.
    uint number_of_siblings(const iterator_base& it) const {
      nodeType* pos=it.node;
      uint ret=0;
      // count forward
      while (pos.nextSibling &&
          pos.nextSibling!=head &&
          pos.nextSibling!=feet) {
        ++ret;
        pos=pos.nextSibling;
      }
      // count backward
      pos=it.node;
      while (pos.prevSibling &&
          pos.prevSibling!=head &&
          pos.prevSibling!=feet) {
        ++ret;
        pos=pos.prevSibling;
      }

      return ret;
    }
    /// Determine whether node at position is in the subtrees with root in the range.
    bool     is_in_subtree(const iterator_base& position, const iterator_base& begin,
                    const iterator_base& end) const {
      // FIXME: this should be optimised.
      pre_order_iterator tmp=begin;
      while (tmp!=end) {
        if (tmp==position) return true;
        ++tmp;
      }
      return false;
    }

    /// Determine whether the iterator is an 'end' iterator and thus not actually pointing to a node.
    bool     is_valid(const iterator_base& it) const {
      if (it.node==null || it.node==feet || it.node==head) return false;
      else return true;
    }
    /// Find the lowest common ancestor of two nodes, that is, the deepest node such that
    /// both nodes are descendants of it.
    iterator lowest_common_ancestor(const iterator_base& one, const iterator_base& two) const {
      std::set<iterator, iterator_base_less> parents;

      // Walk up from 'one' storing all parents.
      iterator walk=one;
      do {
        walk=parent(walk);
        parents.insert(walk);
      } while( is_valid(parent(walk)) );

      // Walk up from 'two' until we encounter a node in parents.
      walk=two;
      do {
        walk=parent(walk);
        if(parents.find(walk) != parents.end()) break;
      } while( is_valid(parent(walk)) );

      return walk;
    }

    /// Determine the index of a node in the range of siblings to which it belongs.
    uint index(sibling_iterator it) const {
      uint ind=0;
      if (it.node.parent==null) {
        while (it.node.prevSibling!=head) {
          it.node=it.node.prevSibling;
          ++ind;
        }
      }
      else {
        while (it.node.prevSibling!=null) {
          it.node=it.node.prevSibling;
          ++ind;
        }
      }
      return ind;
    }
    /// Inverse of 'index': return the n-th child of the node at position.
    static sibling_iterator child(const iterator_base& position, uint num) {
      nodeType* tmp=position.node.firstChild;
      while (num--) {
        assert(tmp!=null);
        tmp=tmp.nextSibling;
      }
      return tmp;
    }
    /// Return iterator to the sibling indicated by index
    sibling_iterator sibling(const iterator_base& it, uint num) {
      nodeType* tmp;
      if (it.node.parent==null) {
        tmp=head.nextSibling;
        while (num) {
          tmp = tmp.nextSibling;
          --num;
        }
      }
      else {
        tmp=it.node.parent.firstChild;
        while (num) {
          assert(tmp!=null);
          tmp = tmp.nextSibling;
          --num;
        }
      }
      return tmp;
    }
+/
    /// For debugging only: verify internal consistency by inspecting all pointers in the tree
    /// (which will also trigger a valgrind error in case something got corrupted).
    void debug_verify_consistency() /*const*/ {
      iterator it=begin();
      while (it!=end()) {
        if (it.node.parent!=null) {
          if (it.node.prevSibling==null)
            assert(it.node.parent.firstChild==it.node);
          else
            assert(it.node.prevSibling.nextSibling==it.node);
          if (it.node.nextSibling==null)
            assert(it.node.parent.lastChild==it.node);
          else
            assert(it.node.nextSibling.prevSibling==it.node);
        }
        ++it;
      }
    }
/+
    /// Comparator class for iterators (compares pointer values; why doesn't this work automatically?)
    class iterator_base_less {
      public:
        bool operator()(const typename tree<T, tree_node_allocator>::iterator_base& one,
                   const typename tree<T, tree_node_allocator>::iterator_base& two) const
          {
          return one.node < two.node;
          }
    }
+/
  private:
////    tree_node_allocator alloc_;
    void head_initialise_() {
        head = cast(nodeType*)Alloc.instance.allocate(nodeType.sizeof).ptr; //alloc_.allocate(1,0); // MSVC does not have default second argument
        feet = cast(nodeType*)Alloc.instance.allocate(nodeType.sizeof).ptr; //alloc_.allocate(1,0);

        head.parent      = null;
        head.firstChild  = null;
        head.lastChild   = null;
        head.prevSibling = null; //head;
        head.nextSibling = feet; //head;

        feet.parent      = null;
        feet.firstChild  = null;
        feet.lastChild   = null;
        feet.prevSibling = head;
        feet.nextSibling = null;
    }
/+
    void copy_(const ref Tree other) {
      clear();
      pre_order_iterator it=other.begin(), to=begin();
      while (it!=other.end()) {
        to=insert(to, (*it));
        it.skip_children();
        ++it;
      }
      to = begin();
      it = other.begin();
      while (it != other.end()) {
        to = replace(to, it);
        to.skip_children();
        it.skip_children();
        ++to;
        ++it;
      }
    }
      /// Comparator class for two nodes of a tree (used for sorting and searching).
    template<class StrictWeakOrdering>
    class compare_nodes {
      public:
        compare_nodes(StrictWeakOrdering comp) : comp_(comp) {};

        bool operator()(const nodeType* a, const nodeType* b)
        {
          return comp_(a.data, b.data);
        }
      private:
        StrictWeakOrdering comp_;
    }
+/
} // struct Tree

//template <class T, class tree_node_allocator>
//class iterator_base_less {
//  public:
//    bool operator()(const typename tree<T, tree_node_allocator>::iterator_base& one,
//              const typename tree<T, tree_node_allocator>::iterator_base& two) const
//      {
//      txtout << "operatorclass<" << one.node < two.node << std::endl;
//      return one.node < two.node;
//      }
//};

// template <class T, class tree_node_allocator>
// bool operator<(const typename tree<T, tree_node_allocator>::iterator& one,
//           const typename tree<T, tree_node_allocator>::iterator& two)
//   {
//   txtout << "operator< " << one.node < two.node << std::endl;
//   if(one.node < two.node) return true;
//   return false;
//   }
//
// template <class T, class tree_node_allocator>
// bool operator==(const typename tree<T, tree_node_allocator>::iterator& one,
//           const typename tree<T, tree_node_allocator>::iterator& two)
//   {
//   txtout << "operator== " << one.node == two.node << std::endl;
//   if(one.node == two.node) return true;
//   return false;
//   }
//
// template <class T, class tree_node_allocator>
// bool operator>(const typename tree<T, tree_node_allocator>::iterator_base& one,
//           const typename tree<T, tree_node_allocator>::iterator_base& two)
//   {
//   txtout << "operator> " << one.node < two.node << std::endl;
//   if(one.node > two.node) return true;
//   return false;
//   }



// Tree


// template <class T, class tree_node_allocator>
// template <class iter>
// iter tree<T, tree_node_allocator>::insert_subtree(sibling_iterator position, iter subtree)
//   {
//   // insert dummy
//   iter it(insert(position, value_type()));
//   // replace dummy with subtree
//   return replace(it, subtree);
//   }



// specialisation for sibling_iterators


// template <class BinaryPredicate>
// tree<T, tree_node_allocator>::iterator tree<T, tree_node_allocator>::find_subtree(
//   sibling_iterator subfrom, sibling_iterator subto, iterator from, iterator to,
//   BinaryPredicate fun) const
//   {
//   assert(1==0); // this routine is not finished yet.
//   while(from!=to) {
//     if(fun(*subfrom, *from)) {
//
//       }
//     }
//   return to;
//   }
unittest {
    import std.stdio;
    import std.array; // : appender, Appender;
    import std.algorithm.comparison : equal;
    import core.memory : GC;

    writeln("Testing tree_k_ary");
    alias TreeType = Tree!(const(char)[]);
    string root_F = "F";
    auto  t = TreeType(root_F); // will hold the tree shown in https://en.wikipedia.org/wiki/Tree_traversal#Pre-order
    writeln("PASSED: Tree(T, Alloc=GCAllocator).  this(const ref T x)  with: [T: const(char)[], Alloc: GCAllocator] for node F");
    auto pos_root = t.begin();
    writeln("PASSED: Tree.  pre_order_iterator  begin()");
    {
        string child_B = "B";
        auto pos_B  = t.append_child(pos_root, child_B);
        writeln("PASSED: Tree.  Iter append_child(Iter)(Iter position, const ref T x)  with: [Iter: pre_order_iterator] for node B");

        string child_A = "A";
        auto pos_A  = t.append_child(pos_B, child_A);
        writeln("PASSED: Tree.  Iter append_child(Iter)(Iter position, const ref T x)  with: [Iter: pre_order_iterator] for node A");
        string child_D = "D";
        auto pos_D  = t.insert_after(pos_A, child_D);
        writeln("PASSED: Tree.  Iter insert_after(Iter)(Iter position, const ref T x)  with: [Iter: pre_order_iterator] for node D");

        string child_C = "C";
        t.append_child(pos_D, child_C);
        writeln("PASSED: Tree.  Iter append_child(Iter)(Iter position, const ref T x)  with: [Iter: pre_order_iterator] for node C");
        string child_E = "E";
        auto pos_E = t.append_child(pos_D, child_E);
        writeln("PASSED: Tree.  Iter append_child(Iter)(Iter position, const ref T x)  with: [Iter: pre_order_iterator] for node E");
////
        string child_G = "G";
        auto pos_G  = t.append_child(pos_root, child_G);
        writeln("PASSED: Tree.  Iter append_child(Iter)(Iter position, const ref T x)  with: [Iter: pre_order_iterator] for node G");

        string child_I = "I";
        auto pos_I  = t.append_child(pos_G, child_I);
        writeln("PASSED: Tree.  Iter append_child(Iter)(Iter position, const ref T x)  with: [Iter: pre_order_iterator] for node I");

        string child_H = "H";
        t.append_child(pos_I, child_H);
        writeln("PASSED: Tree.  Iter append_child(Iter)(Iter position, const ref T x)  with: [Iter: pre_order_iterator] for node H");

//    assert(pos_E.node);
//    writeln(*pos_E.node);
        auto pos_E_too = TreeType.last_child(pos_D);
//    assert(pos_E_too.node);
//    writeln(*pos_E_too.node);

        assert(pos_E.opEquals(pos_E_too));
//  assert(pos_E ==       pos_E_too); // core.exception.AssertError@../../.dub/packages/tree_k_ary-0.0.1/tree_k_ary/source/tree_k_ary.d(2471): unittest failure

        auto w = appender!string;
        // pre-allocate space for at least 10 elements (this avoids costly reallocations)
        w.reserve(20);
        assert(w.capacity >= 20);

        foreach (val; t.preOrderRange(t.begin(), t.end()))
            w ~= val ~ " ";
        assert(equal(w.data, "F B A D C E G I H "));
    }
    GC.collect();
    writeln("DONE: GC.collect(). The next test is a repetition in order to check, whether the tree is still there in memory, unchanged");
    auto w = appender!string;
    w.reserve(20);
    foreach (i, val; t.preOrderRange(t.begin(), t.end())) {
        writefln("%s: %s", i, val);
        w ~= val ~ " ";
    }
//    writeln(w.data);
    assert(equal(w.data, "F B A D C E G I H "));
    writeln("PASSED: t.preOrderRange(t.begin(), t.end())");

    auto wr = appender!string;
    wr.reserve(20);
    foreach_reverse (val; t.preOrderRange(t.begin(), t.end()))
        wr ~= val ~ " ";
//    writeln(wr.data);
    assert(equal(wr.data, "H I G E C D A B F "));
    writeln("PASSED: reverse: t.preOrderRange(t.begin(), t.end())");
///
    auto y = appender!string;
    y.reserve(20);
    foreach (val; t.postOrderRange(t.begin_post(), t.end_post()))
        y ~= val ~ " ";
//    writeln(y.data);
    assert(equal(y.data, "A C E D B H I G F "));
    writeln("PASSED: t.postOrderRange(t.begin_post(), t.end_post())");

    auto z = appender!string;
    z.reserve(20);
    foreach (val; t.siblingRange(t.begin(pos_root), t.end(pos_root)))
        z ~= val ~ " ";
//    writeln(z.data);
    assert(equal(z.data, "B G "));
    writeln("PASSED: t.siblingRange(t.begin(pos_root), t.end(pos_root))");

    auto zr = appender!string;
    zr.reserve(20);
    foreach_reverse (val; t.siblingRange(t.begin(pos_root), t.end(pos_root)))
        zr ~= val ~ " ";
//    writeln(zr.data);
    assert(equal(zr.data, "G B "));
    writeln("PASSED: reverse: t.siblingRange(t.begin(pos_root), t.end(pos_root))");

    auto bfi = new TreeType.breadth_first_iterator(pos_root);
//    bfi += 1; assert(bfi.node); assert(bfi.node.data == "B"); TODO this causes a crash currently

    t.clear(); // Tree's destructor will do that as well; multiple clear just have no effect
    writeln("PASSED: t.clear()");
}
